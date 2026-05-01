use badvpn_common::BadVpnResult;

#[derive(Debug, Default)]
pub struct MihomoSupervisor {
    running: bool,
}

impl MihomoSupervisor {
    pub async fn start(&mut self) -> BadVpnResult<()> {
        self.running = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> BadVpnResult<()> {
        self.running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}
