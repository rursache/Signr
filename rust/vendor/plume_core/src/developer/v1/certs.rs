use serde_json::json;
use uuid::Uuid;

use super::{DeveloperSession, RequestType};
use crate::developer_endpoint;

use crate::Error;

impl DeveloperSession {
    pub async fn v1_submit_cert_csr(
        &self,
        team_id: &String,
        csr_data: String,
        machine_name: &String,
    ) -> Result<(), Error> {
        let endpoint = developer_endpoint!("/v1/certificates");

        let body = json!({
            "data": {
                "type": "certificates",
                "attributes": {
                    "certificatesType": "DEVELOPMENT",
                    "teamId": team_id,
                    "csrContent": csr_data,
                    "machineName": machine_name,
                    "machineId": Uuid::new_v4().to_string().to_uppercase()
                }
            }
        });

        let _ = self
            .v1_send_request(&endpoint, Some(body), Some(RequestType::Post))
            .await?;
        todo!("v1_submit_cert_csr");
    }
}
