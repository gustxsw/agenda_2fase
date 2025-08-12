import express from 'express';
import { pool } from '../db.js';
import { authenticate, authorize } from '../middleware/auth.js';

const router = express.Router();

// Create appointments table if it doesn't exist
const createAppointmentsTable = async () => {
  try {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
        location_id INTEGER REFERENCES attendance_locations(id) ON DELETE SET NULL,
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        notes TEXT,
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        -- Ensure at least one patient type is specified
        CONSTRAINT check_patient_specified CHECK (
          (private_patient_id IS NOT NULL)::int + 
          (client_id IS NOT NULL)::int + 
          (dependent_id IS NOT NULL)::int = 1
        ),
        
        -- Ensure valid status
        CONSTRAINT check_status CHECK (
          status IN ('scheduled', 'confirmed', 'completed', 'cancelled', 'no_show', 'rescheduled')
        )
      );
      
      -- Create indexes for better performance
      CREATE INDEX IF NOT EXISTS idx_appointments_professional_date 
        ON appointments(professional_id, appointment_date);
      CREATE INDEX IF NOT EXISTS idx_appointments_status 
        ON appointments(status);
      CREATE INDEX IF NOT EXISTS idx_appointments_date_time 
        ON appointments(appointment_date, appointment_time);
    `;

    await pool.query(createTableQuery);
    console.log('✅ Appointments table created/verified');
  } catch (error) {
    console.error('❌ Error creating appointments table:', error);
  }
};

// Initialize table on module load
createAppointmentsTable();

// Get all appointments for a professional
router.get('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('📅 Fetching appointments for professional:', professionalId);

    let query = `
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.notes,
        a.value,
        a.status,
        a.private_patient_id,
        a.client_id,
        a.dependent_id,
        a.created_at,
        a.updated_at,
        
        -- Patient info
        COALESCE(pp.name, c.name, d.name) as patient_name,
        COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf,
        COALESCE(pp.phone, c.phone) as patient_phone,
        
        -- Service info
        s.name as service_name,
        s.base_price as service_base_price,
        
        -- Location info
        al.name as location_name,
        al.address as location_address
        
      FROM appointments a
      LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
      LEFT JOIN users c ON a.client_id = c.id
      LEFT JOIN dependents d ON a.dependent_id = d.id
      LEFT JOIN services s ON a.service_id = s.id
      LEFT JOIN attendance_locations al ON a.location_id = al.id
      WHERE a.professional_id = $1
    `;

    const params = [professionalId];

    if (start_date && end_date) {
      query += ` AND a.appointment_date BETWEEN $2 AND $3`;
      params.push(start_date, end_date);
    }

    query += ` ORDER BY a.appointment_date, a.appointment_time`;

    const result = await pool.query(query, params);

    console.log('✅ Found appointments:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new appointment
router.post('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status = 'scheduled'
    } = req.body;

    const professionalId = req.user.id;

    console.log('📅 Creating appointment:', req.body);

    // Validate required fields
    if (!service_id || !appointment_date || !appointment_time || !value) {
      return res.status(400).json({ 
        message: 'Serviço, data, hora e valor são obrigatórios' 
      });
    }

    // Validate that exactly one patient type is provided
    const patientCount = [private_patient_id, client_id, dependent_id].filter(Boolean).length;
    if (patientCount !== 1) {
      return res.status(400).json({ 
        message: 'É necessário especificar exatamente um tipo de paciente' 
      });
    }

    // Check for scheduling conflicts
    const conflictQuery = `
      SELECT id FROM appointments 
      WHERE professional_id = $1 
      AND appointment_date = $2 
      AND appointment_time = $3
      AND status NOT IN ('cancelled', 'no_show')
    `;

    const conflictResult = await pool.query(conflictQuery, [
      professionalId,
      appointment_date,
      appointment_time
    ]);

    if (conflictResult.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Já existe um agendamento para este horário' 
      });
    }

    // Create appointment
    const insertQuery = `
      INSERT INTO appointments (
        professional_id,
        private_patient_id,
        client_id,
        dependent_id,
        service_id,
        appointment_date,
        appointment_time,
        location_id,
        notes,
        value,
        status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `;

    const result = await pool.query(insertQuery, [
      professionalId,
      private_patient_id || null,
      client_id || null,
      dependent_id || null,
      service_id,
      appointment_date,
      appointment_time,
      location_id || null,
      notes || null,
      value,
      status
    ]);

    console.log('✅ Appointment created:', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update appointment
router.put('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      private_patient_id,
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value
    } = req.body;

    const professionalId = req.user.id;

    console.log('📅 Updating appointment:', id, req.body);

    // Verify appointment belongs to professional
    const checkQuery = `
      SELECT id FROM appointments 
      WHERE id = $1 AND professional_id = $2
    `;

    const checkResult = await pool.query(checkQuery, [id, professionalId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    // Check for scheduling conflicts (excluding current appointment)
    if (appointment_date && appointment_time) {
      const conflictQuery = `
        SELECT id FROM appointments 
        WHERE professional_id = $1 
        AND appointment_date = $2 
        AND appointment_time = $3
        AND id != $4
        AND status NOT IN ('cancelled', 'no_show')
      `;

      const conflictResult = await pool.query(conflictQuery, [
        professionalId,
        appointment_date,
        appointment_time,
        id
      ]);

      if (conflictResult.rows.length > 0) {
        return res.status(400).json({ 
          message: 'Já existe um agendamento para este horário' 
        });
      }
    }

    // Update appointment
    const updateQuery = `
      UPDATE appointments SET
        private_patient_id = $1,
        service_id = $2,
        appointment_date = $3,
        appointment_time = $4,
        location_id = $5,
        notes = $6,
        value = $7,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $8 AND professional_id = $9
      RETURNING *
    `;

    const result = await pool.query(updateQuery, [
      private_patient_id || null,
      service_id,
      appointment_date,
      appointment_time,
      location_id || null,
      notes || null,
      value,
      id,
      professionalId
    ]);

    console.log('✅ Appointment updated:', result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update appointment status only
router.put('/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const professionalId = req.user.id;

    console.log('📅 Updating appointment status:', { id, status, professionalId });

    // Validate status
    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled', 'no_show', 'rescheduled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    // Verify appointment belongs to professional
    const checkQuery = `
      SELECT id FROM appointments 
      WHERE id = $1 AND professional_id = $2
    `;

    const checkResult = await pool.query(checkQuery, [id, professionalId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    // Update status
    const updateQuery = `
      UPDATE appointments SET
        status = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND professional_id = $3
      RETURNING *
    `;

    const result = await pool.query(updateQuery, [status, id, professionalId]);

    console.log('✅ Appointment status updated:', result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating appointment status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete appointment
router.delete('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const professionalId = req.user.id;

    console.log('📅 Deleting appointment:', { id, professionalId });

    // Verify appointment belongs to professional
    const checkQuery = `
      SELECT id FROM appointments 
      WHERE id = $1 AND professional_id = $2
    `;

    const checkResult = await pool.query(checkQuery, [id, professionalId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    // Delete appointment
    const deleteQuery = `
      DELETE FROM appointments 
      WHERE id = $1 AND professional_id = $2
    `;

    await pool.query(deleteQuery, [id, professionalId]);

    console.log('✅ Appointment deleted');
    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;