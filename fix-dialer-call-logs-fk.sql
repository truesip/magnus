-- Fix dialer_call_logs foreign key to allow NULL ai_agent_id for audio-only campaigns
ALTER TABLE dialer_call_logs
DROP FOREIGN KEY fk_dialer_logs_agent;

ALTER TABLE dialer_call_logs
ADD CONSTRAINT fk_dialer_logs_agent
FOREIGN KEY (ai_agent_id) 
REFERENCES ai_agents(id) 
ON DELETE SET NULL;

-- Ensure ai_agent_id column allows NULL
ALTER TABLE dialer_call_logs
MODIFY COLUMN ai_agent_id INT NULL;
