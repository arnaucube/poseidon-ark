use ark_bn254::Fr;
use ark_ff::fields::Field;
use ark_std::str::FromStr;
use ark_std::Zero;
use core::ops::{AddAssign, MulAssign};

mod constants;

#[derive(Debug)]
pub struct Constants {
    pub c: Vec<Vec<Fr>>,
    pub m: Vec<Vec<Vec<Fr>>>,
    pub n_rounds_f: usize,
    pub n_rounds_p: Vec<usize>,
}

pub fn load_constants() -> Constants {
    let (c_str, m_str) = constants::constants();
    let mut c: Vec<Vec<Fr>> = Vec::new();
    for i in 0..c_str.len() {
        let mut cci: Vec<Fr> = Vec::new();
        for j in 0..c_str[i].len() {
            let b: Fr = Fr::from_str(c_str[i][j]).unwrap();
            cci.push(b);
        }
        c.push(cci);
    }
    let mut m: Vec<Vec<Vec<Fr>>> = Vec::new();
    for i in 0..m_str.len() {
        let mut mi: Vec<Vec<Fr>> = Vec::new();
        for j in 0..m_str[i].len() {
            let mut mij: Vec<Fr> = Vec::new();
            for k in 0..m_str[i][j].len() {
                let b: Fr = Fr::from_str(m_str[i][j][k]).unwrap();
                mij.push(b);
            }
            mi.push(mij);
        }
        m.push(mi);
    }
    Constants {
        c,
        m,
        n_rounds_f: 8,
        n_rounds_p: vec![56, 57, 56, 60, 60, 63, 64, 63],
    }
}

pub struct Poseidon {
    constants: Constants,
}
impl Poseidon {
    pub fn new() -> Poseidon {
        Poseidon {
            constants: load_constants(),
        }
    }
    pub fn ark(&self, state: &mut Vec<Fr>, c: &[Fr], it: usize) {
        for i in 0..state.len() {
            state[i].add_assign(&c[it + i]);
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut Vec<Fr>, i: usize) {
        if i < n_rounds_f / 2 || i >= n_rounds_f / 2 + n_rounds_p {
            for j in 0..state.len() {
                let aux = state[j];
                state[j] = state[j].square();
                state[j] = state[j].square();
                state[j].mul_assign(&aux);
            }
        } else {
            let aux = state[0];
            state[0] = state[0].square();
            state[0] = state[0].square();
            state[0].mul_assign(&aux);
        }
    }

    pub fn mix(&self, state: &Vec<Fr>, m: &[Vec<Fr>]) -> Vec<Fr> {
        let mut new_state: Vec<Fr> = Vec::new();
        for i in 0..state.len() {
            new_state.push(Fr::zero());
            for j in 0..state.len() {
                let mut mij = m[i][j];
                mij.mul_assign(&state[j]);
                new_state[i].add_assign(&mij);
            }
        }
        new_state.clone()
    }

    pub fn hash(&self, inp: Vec<Fr>) -> Result<Fr, String> {
        let t = inp.len() + 1;
        if inp.is_empty() || inp.len() >= self.constants.n_rounds_p.len() - 1 {
            return Err("Wrong inputs length".to_string());
        }
        let n_rounds_f = self.constants.n_rounds_f.clone();
        let n_rounds_p = self.constants.n_rounds_p[t - 2].clone();

        let mut state = vec![Fr::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        Ok(state[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_constants() {
        let cons = load_constants();
        assert_eq!(
            cons.c[0][0].to_string(),
            "4417881134626180770308697923359573201005643519861877412381846989312604493735"
        );
        assert_eq!(
            cons.c[cons.c.len() - 1][0].to_string(),
            "14715728137766105031387583973733149375806784983272780095398485311648630967927"
        );
        assert_eq!(
            cons.m[0][0][0].to_string(),
            "2910766817845651019878574839501801340070030115151021261302834310722729507541"
        );
        assert_eq!(
            cons.m[cons.m.len() - 1][0][0].to_string(),
            "708458300293891745856425423607721463509413916954480913172999113933455141974"
        );
    }

    #[test]
    fn test_hash() {
        let b0: Fr = Fr::from_str("0").unwrap();
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();
        let b3: Fr = Fr::from_str("3").unwrap();
        let b4: Fr = Fr::from_str("4").unwrap();
        let b5: Fr = Fr::from_str("5").unwrap();
        let b6: Fr = Fr::from_str("6").unwrap();

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        let poseidon = Poseidon::new();
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        let poseidon = Poseidon::new();
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let poseidon = Poseidon::new();
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "1018317224307729531995786483840663576608797660851238720571059489595066344487"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let poseidon = Poseidon::new();
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "15336558801450556532856248569924170992202208561737609669134139141992924267169"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let poseidon = Poseidon::new();
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "5811595552068139067952687508729883632420015185677766880877743348592482390548"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "12263118664590987767234828103155242843640892839966517009184493198782366909018"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b5.clone());
        big_arr.push(b6.clone());
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        );
    }
}
