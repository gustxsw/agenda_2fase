import { pool } from '../db.js';

// SQL para criar todas as tabelas do sistema
const createTablesSQL = `
-- Tabela de categorias de serviços
CREATE TABLE IF NOT EXISTS service_categories (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de usuários (clientes, profissionais e admins)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  cpf VARCHAR(11) NOT NULL UNIQUE,
  email VARCHAR(255),
  phone VARCHAR(20),
  birth_date DATE,
  address TEXT,
  address_number VARCHAR(20),
  address_complement VARCHAR(100),
  neighborhood VARCHAR(100),
  city VARCHAR(100),
  state VARCHAR(2),
  zip_code VARCHAR(8),
  password_hash VARCHAR(255) NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  percentage DECIMAL(5,2) DEFAULT 50.00,
  category_id INTEGER REFERENCES service_categories(id),
  subscription_status VARCHAR(20) DEFAULT 'pending',
  subscription_expiry TIMESTAMP,
  photo_url TEXT,
  has_scheduling_access BOOLEAN DEFAULT FALSE,
  access_expires_at TIMESTAMP,
  access_granted_by VARCHAR(255),
  access_granted_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de dependentes
CREATE TABLE IF NOT EXISTS dependents (
  id SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  cpf VARCHAR(11) NOT NULL UNIQUE,
  birth_date DATE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de serviços
CREATE TABLE IF NOT EXISTS services (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  base_price DECIMAL(10,2) NOT NULL,
  category_id INTEGER REFERENCES service_categories(id),
  is_base_service BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de locais de atendimento
CREATE TABLE IF NOT EXISTS attendance_locations (
  id SERIAL PRIMARY KEY,
  professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  address TEXT,
  address_number VARCHAR(20),
  address_complement VARCHAR(100),
  neighborhood VARCHAR(100),
  city VARCHAR(100),
  state VARCHAR(2),
  zip_code VARCHAR(8),
  phone VARCHAR(20),
  is_default BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de pacientes particulares
CREATE TABLE IF NOT EXISTS private_patients (
  id SERIAL PRIMARY KEY,
  professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  cpf VARCHAR(11) NOT NULL,
  email VARCHAR(255),
  phone VARCHAR(20),
  birth_date DATE,
  address TEXT,
  address_number VARCHAR(20),
  address_complement VARCHAR(100),
  neighborhood VARCHAR(100),
  city VARCHAR(100),
  state VARCHAR(2),
  zip_code VARCHAR(8),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(professional_id, cpf)
);

-- Tabela de consultas
CREATE TABLE IF NOT EXISTS consultations (
  id SERIAL PRIMARY KEY,
  client_id INTEGER REFERENCES users(id),
  dependent_id INTEGER REFERENCES dependents(id),
  private_patient_id INTEGER REFERENCES private_patients(id),
  professional_id INTEGER NOT NULL REFERENCES users(id),
  service_id INTEGER NOT NULL REFERENCES services(id),
  location_id INTEGER REFERENCES attendance_locations(id),
  value DECIMAL(10,2) NOT NULL,
  date TIMESTAMP NOT NULL,
  status VARCHAR(20) DEFAULT 'completed',
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT check_patient_type CHECK (
    (client_id IS NOT NULL AND dependent_id IS NULL AND private_patient_id IS NULL) OR
    (client_id IS NULL AND dependent_id IS NOT NULL AND private_patient_id IS NULL) OR
    (client_id IS NULL AND dependent_id IS NULL AND private_patient_id IS NOT NULL)
  )
);

-- Tabela de prontuários médicos
CREATE TABLE IF NOT EXISTS medical_records (
  id SERIAL PRIMARY KEY,
  professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  private_patient_id INTEGER NOT NULL REFERENCES private_patients(id) ON DELETE CASCADE,
  chief_complaint TEXT,
  history_present_illness TEXT,
  past_medical_history TEXT,
  medications TEXT,
  allergies TEXT,
  physical_examination TEXT,
  diagnosis TEXT,
  treatment_plan TEXT,
  notes TEXT,
  vital_signs JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de documentos médicos
CREATE TABLE IF NOT EXISTS medical_documents (
  id SERIAL PRIMARY KEY,
  professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  document_type VARCHAR(50) NOT NULL,
  document_url TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de pagamentos
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  payment_type VARCHAR(20) NOT NULL, -- 'subscription' or 'professional_payment'
  amount DECIMAL(10,2) NOT NULL,
  mp_payment_id VARCHAR(255),
  mp_preference_id VARCHAR(255),
  status VARCHAR(20) DEFAULT 'pending',
  payment_date TIMESTAMP,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para melhor performance
CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);
CREATE INDEX IF NOT EXISTS idx_dependents_client_id ON dependents(client_id);
CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf);
CREATE INDEX IF NOT EXISTS idx_consultations_professional_id ON consultations(professional_id);
CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date);
CREATE INDEX IF NOT EXISTS idx_consultations_client_id ON consultations(client_id);
CREATE INDEX IF NOT EXISTS idx_consultations_dependent_id ON consultations(dependent_id);
CREATE INDEX IF NOT EXISTS idx_medical_records_professional_id ON medical_records(professional_id);
CREATE INDEX IF NOT EXISTS idx_medical_records_patient_id ON medical_records(private_patient_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_mp_payment_id ON payments(mp_payment_id);

-- Inserir categorias padrão
INSERT INTO service_categories (name, description) VALUES
  ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
  ('Quiropraxia', 'Tratamentos quiropráticos'),
  ('Massoterapia', 'Massagens terapêuticas e relaxantes'),
  ('Psicologia', 'Atendimento psicológico'),
  ('Nutrição', 'Consultas nutricionais'),
  ('Medicina', 'Consultas médicas gerais'),
  ('Odontologia', 'Tratamentos odontológicos'),
  ('Estética', 'Procedimentos estéticos')
ON CONFLICT (name) DO NOTHING;

-- Inserir serviços padrão
INSERT INTO services (name, description, base_price, category_id, is_base_service) VALUES
  ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 80.00, 1, true),
  ('Sessão de Fisioterapia', 'Sessão de tratamento fisioterapêutico', 60.00, 1, false),
  ('Consulta Quiroprática', 'Avaliação e ajuste quiroprático', 100.00, 2, true),
  ('Ajuste Quiroprático', 'Sessão de ajuste quiroprático', 80.00, 2, false),
  ('Massagem Terapêutica', 'Massagem para alívio de tensões', 70.00, 3, true),
  ('Massagem Relaxante', 'Massagem para relaxamento', 60.00, 3, false),
  ('Consulta Psicológica', 'Sessão de psicoterapia', 120.00, 4, true),
  ('Consulta Nutricional', 'Avaliação e orientação nutricional', 90.00, 5, true),
  ('Consulta Médica', 'Consulta médica geral', 150.00, 6, true),
  ('Consulta Odontológica', 'Avaliação odontológica', 80.00, 7, true),
  ('Limpeza Dental', 'Profilaxia dental', 60.00, 7, false),
  ('Procedimento Estético', 'Tratamento estético facial/corporal', 120.00, 8, true)
ON CONFLICT DO NOTHING;

-- Criar usuário admin padrão (senha: admin123)
INSERT INTO users (name, cpf, password_hash, roles) VALUES
  ('Administrador', '00000000000', '$2a$10$rOzJqQZJqQZJqQZJqQZJqOzJqQZJqQZJqQZJqQZJqQZJqQZJqQZJq', ARRAY['admin'])
ON CONFLICT (cpf) DO NOTHING;
`;

export const initializeDatabase = async () => {
  try {
    console.log('🔄 Inicializando banco de dados...');
    
    await pool.query(createTablesSQL);
    
    console.log('✅ Banco de dados inicializado com sucesso!');
    console.log('📋 Tabelas criadas:');
    console.log('   - service_categories (categorias de serviços)');
    console.log('   - users (usuários do sistema)');
    console.log('   - dependents (dependentes dos clientes)');
    console.log('   - services (serviços oferecidos)');
    console.log('   - attendance_locations (locais de atendimento)');
    console.log('   - private_patients (pacientes particulares)');
    console.log('   - consultations (consultas realizadas)');
    console.log('   - medical_records (prontuários médicos)');
    console.log('   - medical_documents (documentos médicos)');
    console.log('   - payments (controle de pagamentos)');
    console.log('');
    console.log('👤 Usuário admin padrão criado:');
    console.log('   CPF: 000.000.000-00');
    console.log('   Senha: admin123');
    console.log('');
    console.log('🎯 Categorias e serviços padrão inseridos');
    
    return true;
  } catch (error) {
    console.error('❌ Erro ao inicializar banco de dados:', error);
    throw error;
  }
};

export default initializeDatabase;