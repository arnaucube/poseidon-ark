pub fn constants() -> (Vec<Vec<&'static str>>, Vec<Vec<Vec<&'static str>>>) {
    let mut c_str = Vec::new();
    let mut m_str = Vec::new();

    #[cfg(feature = "poseidon-1")]
    {
        c_str.push(poseidon_1::c_constants());
        m_str.push(poseidon_1::m_constants());
    }

    #[cfg(feature = "poseidon-2")]
    {
        c_str.push(poseidon_2::c_constants());
        m_str.push(poseidon_2::m_constants());
    }

    #[cfg(feature = "poseidon-3")]
    {
        c_str.push(poseidon_3::c_constants());
        m_str.push(poseidon_3::m_constants());
    }

    #[cfg(feature = "poseidon-4")]
    {
        c_str.push(poseidon_4::c_constants());
        m_str.push(poseidon_4::m_constants());
    }

    #[cfg(feature = "poseidon-5")]
    {
        c_str.push(poseidon_5::c_constants());
        m_str.push(poseidon_5::m_constants());
    }

    #[cfg(feature = "poseidon-6")]
    {
        c_str.push(poseidon_6::c_constants());
        m_str.push(poseidon_6::m_constants());
    }

    #[cfg(feature = "poseidon-7")]
    {
        c_str.push(poseidon_7::c_constants());
        m_str.push(poseidon_7::m_constants());
    }

    #[cfg(feature = "poseidon-8")]
    {
        c_str.push(poseidon_8::c_constants());
        m_str.push(poseidon_8::m_constants());
    }

    #[cfg(feature = "poseidon-9")]
    {
        c_str.push(poseidon_9::c_constants());
        m_str.push(poseidon_9::m_constants());
    }

    #[cfg(feature = "poseidon-10")]
    {
        c_str.push(poseidon_10::c_constants());
        m_str.push(poseidon_10::m_constants());
    }

    #[cfg(feature = "poseidon-11")]
    {
        c_str.push(poseidon_11::c_constants());
        m_str.push(poseidon_11::m_constants());
    }

    #[cfg(feature = "poseidon-12")]
    {
        c_str.push(poseidon_12::c_constants());
        m_str.push(poseidon_12::m_constants());
    }

    #[cfg(feature = "poseidon-13")]
    {
        c_str.push(poseidon_13::c_constants());
        m_str.push(poseidon_13::m_constants());
    }

    #[cfg(feature = "poseidon-14")]
    {
        c_str.push(poseidon_14::c_constants());
        m_str.push(poseidon_14::m_constants());
    }

    #[cfg(feature = "poseidon-15")]
    {
        c_str.push(poseidon_15::c_constants());
        m_str.push(poseidon_15::m_constants());
    }

    #[cfg(feature = "poseidon-16")]
    {
        c_str.push(poseidon_16::c_constants());
        m_str.push(poseidon_16::m_constants());
    }

    (c_str, m_str)
}
