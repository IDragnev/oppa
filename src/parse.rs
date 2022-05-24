use std::fmt;
use nom::error::{
    ParseError as NomParseError,
    ErrorKind as NomErrorKind,
};

pub type Input<'a> = &'a [u8];
pub type Result<'a, T> = nom::IResult<Input<'a>, T, Error<Input<'a>>>;

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
    Custom(String),
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> Error<I> {
    pub fn custom(input: I, msg: String) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Custom(msg))],
        }
    }
}

impl<I> NomParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

impl<'a> fmt::Debug for Error<&'a [u8]> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "/!\\ nente parsing error\n")?;

        let mut shown_input = None;
        let margin_left = 4;
        let margin_str = " ".repeat(margin_left);

        // maximum amount of binary data we'll dump per line
        let maxlen = 60;

        // given a big slice, an offset, and a length, attempt to show
        // some data before, some data after, and highlight which part
        // we're talking about with tildes.
        let print_slice =
            |f: &mut fmt::Formatter, s: &[u8], offset: usize, len: usize| -> fmt::Result {
                // decide which part of `s` we're going to show.
                let (s, offset, len) = {
                    let avail_after = s.len() - offset;
                    let after = std::cmp::min(avail_after, maxlen / 2);

                    let avail_before = offset;
                    let before = std::cmp::min(avail_before, maxlen / 2);

                    let new_start = offset - before;
                    let new_end = offset + after;
                    let new_offset = before;
                    let new_len = std::cmp::min(new_end - new_start, len);

                    (&s[new_start..new_end], new_offset, new_len)
                };

                write!(f, "{}", margin_str)?;
                for b in s {
                    write!(f, "{:02X} ", b)?;
                }
                write!(f, "\n")?;

                write!(f, "{}", margin_str)?;
                for i in 0..s.len() {
                    // each byte takes three characters, ie "FF "
                    if i == offset + len - 1 {
                        // ..except the last one
                        write!(f, "~~")?;
                    } else if (offset..offset + len).contains(&i) {
                        write!(f, "~~~")?;
                    } else {
                        write!(f, "   ")?;
                    };
                }
                write!(f, "\n")?;

                Ok(())
            };

        for (input, kind) in self.errors.iter().rev() {
            let prefix = match kind {
                ErrorKind::Context(ctx) => format!("...in {}", ctx),
                ErrorKind::Nom(err) => format!("nom error {:?}", err),
                ErrorKind::Custom(msg) => format!("{}", msg),
            };

            write!(f, "{}\n", prefix)?;
            match shown_input {
                None => {
                    shown_input.replace(input);
                    print_slice(f, input, 0, input.len())?;
                }
                Some(parent_input) => {
                    use nom::Offset;
                    let offset = parent_input.offset(input);
                    print_slice(f, parent_input, offset, input.len())?;
                }
            };
        }
        Ok(())
    }
}