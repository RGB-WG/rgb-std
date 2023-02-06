#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum PrevAssignmentParseError {
    #[from]
    InvalidNodeId(amplify::hex::Error),

    InvalidType(ParseIntError),

    InvalidOutputNo(ParseIntError),

    /// invalid node outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for PrevAssignment {
    type Err = PrevAssignmentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(node_id), Some(ty), Some(no), None) => Ok(PrevAssignment {
                node_id: node_id.parse()?,
                ty: ty.parse().map_err(PrevAssignmentParseError::InvalidType)?,
                no: no
                    .parse()
                    .map_err(PrevAssignmentParseError::InvalidOutputNo)?,
            }),
            _ => Err(PrevAssignmentParseError::WrongFormat(s.to_owned())),
        }
    }
}
