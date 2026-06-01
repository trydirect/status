use actix_web::Result;

pub struct JsonCommand {
    line: usize,
    column: usize,
    payload: String,
}

impl JsonCommand {
    pub fn new(line: usize, column: usize, payload: String) -> Self {
        Self {
            line,
            column,
            payload,
        }
    }
}

impl crate::console::commands::CallableTrait for JsonCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let payload: String = std::fs::read_to_string(&self.payload)?;
        let index = line_column_to_index(payload.as_ref(), self.line, self.column);
        let prefix = String::from_utf8(
            <std::string::String as AsRef<[u8]>>::as_ref(&payload)[..index].to_vec(),
        )
        .unwrap();

        println!("{}", prefix);
        Ok(())
    }
}

fn line_column_to_index(u8slice: &[u8], line: usize, column: usize) -> usize {
    let mut l = 1;
    let mut c = 0;
    let mut i = 0;
    for ch in u8slice {
        i += 1;
        match ch {
            b'\n' => {
                l += 1;
                c = 0;
            }
            _ => {
                c += 1;
            }
        }
        if line == l && c == column {
            break;
        }
    }
    return i;
}
