use pyo3::prelude::*;

#[pyfunction]
fn hello_from_bin() -> String {
    "Hello from eventloop!!".to_string()
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_from_bin, m)?)?;
    Ok(())
}
