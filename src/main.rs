use bcrypt;
use md5;
use std::io::stdin;

static ALPHABET_LOWER: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
static ALPHABET_UPPER: [char; 26] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
static NUMBERS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
static SYMBOLS: [char; 16] = ['!', '@', '#', '$', '%', '^', '&', '(', ')', '=', '`', '?', '[', ']', '+', '_'];

fn main() {
    let user_string = get_user_string();
    let user_string_bytes = user_string.as_bytes();

    let digest = md5::compute(user_string_bytes);
    let hash = bcrypt::bcrypt(8, digest.0, user_string_bytes);

    let generated_password = generate_password(&hash);

    println!("Generated password: {}", generated_password);
}

fn generate_password(hash: &[u8; 24]) -> String {
    let pick_alphabet_coefficient = 26.0 / 256.0;
    let pick_num_coefficient = 10.0 / 256.0;
    let pick_symbol_coefficient = 16.0 / 256.0;

    let mut result_string = String::new();

    for i in (0..24).into_iter().step_by(4) {
        let lower_index = (hash[i] as f64 * pick_alphabet_coefficient) as usize;
        let upper_index = (hash[i+1] as f64 * pick_alphabet_coefficient) as usize;
        let num_index = (hash[i+2] as f64 * pick_num_coefficient) as usize;
        let symbol_index = (hash[i+3] as f64 * pick_symbol_coefficient) as usize;
        result_string.push(ALPHABET_LOWER[lower_index]);
        result_string.push(ALPHABET_UPPER[upper_index]);
        result_string.push(NUMBERS[num_index]);
        result_string.push(SYMBOLS[symbol_index]);
    }

    result_string
}

fn get_user_string() -> String {
    println!("Please enter some string to generate password:");
    let mut input_string = String::new();
    let _read_bytes = stdin().read_line(&mut input_string).unwrap();
    input_string = input_string.strip_suffix("\n").unwrap().to_string();
    input_string
}
