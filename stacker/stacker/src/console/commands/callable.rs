pub trait CallableTrait {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>>;
}
