const express = require('express');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

// Get professional's schedule settings
router.get('/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      // Return default settings if none exist
      return res.json({
        professional_id: req.user.id,
        work_days: [1, 2, 3, 4, 5], // Monday to Friday
        work_start_time: '08:00',
        work_end_time: '18:00',
        break_start_time: '12:00',
        break_end_time: '13:00',
        consultation_duration: 60,
        has_scheduling_subscription: true
      });
    }

    // Ensure all professionals have scheduling access
    const settings = result.rows[0];
    settings.has_scheduling_subscription = true;

    res.json(settings);
  } catch (error) {
    console.error('Error fetching schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update professional's schedule settings
router.put('/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      work_days,
      work_start_time,
      work_end_time,
      break_start_time,
      break_end_time,
      consultation_duration
    } = req.body;

    const result = await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         work_days = $2,
         work_start_time = $3,
         work_end_time = $4,
         break_start_time = $5,
         break_end_time = $6,
         consultation_duration = $7,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professional's appointments
router.get('/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    const result = await pool.query(
      `SELECT a.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name,
              COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf,
              s.name as service_name,
              al.name as location_name,
              al.address as location_address
       FROM appointments a
       LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
       LEFT JOIN users c ON a.client_id = c.id
       LEFT JOIN dependents d ON a.dependent_id = d.id
       LEFT JOIN services s ON a.service_id = s.id
       LEFT JOIN attendance_locations al ON a.location_id = al.id
       WHERE a.professional_id = $1
       AND a.appointment_date >= $2
       AND a.appointment_date <= $3
       ORDER BY a.appointment_date, a.appointment_time`,
      [req.user.id, start_date, end_date]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new appointment
router.post('/appointments', authenticate, authorize(['professional']), async (req, res) => {
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
      value
    } = req.body;

    const result = await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, client_id, dependent_id, service_id, 
        appointment_date, appointment_time, location_id, notes, value, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled')
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
       appointment_date, appointment_time, location_id, notes, value]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update appointment
router.put('/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status
    } = req.body;

    const result = await pool.query(
      `UPDATE appointments 
       SET appointment_date = $1, appointment_time = $2, location_id = $3, 
           notes = $4, value = $5, status = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND professional_id = $8
       RETURNING *`,
      [appointment_date, appointment_time, location_id, notes, value, status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete appointment
router.delete('/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM appointments WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;