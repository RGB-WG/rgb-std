use rgb::validation::{ContainerApi, HistoryApi};

pub trait ConsignmentApi {}

pub struct Consignment<C: ConsignmentApi>(pub C);

impl<C: ConsignmentApi> ContainerApi for Consignment<C> {}
impl<C: ConsignmentApi> HistoryApi for Consignment<C> {}
