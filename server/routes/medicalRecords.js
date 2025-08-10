import express from 'express';
import { pool } from '../db.js';
import { authenticate, authorize } from '../middleware/auth.js';

const router = express.Router();

// Get medical records for current professional
router.get('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name,
              COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1
       ORDER BY mr.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get medical records for a patient
router.get('/patient/:patientId/:patientType', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { patientId, patientType } = req.params;

    let whereClause = '';
    if (patientType === 'private') {
      whereClause = 'private_patient_id = $2';
    } else if (patientType === 'client') {
      whereClause = 'client_id = $2';
    } else if (patientType === 'dependent') {
      whereClause = 'dependent_id = $2';
    }

    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1 AND ${whereClause}
       ORDER BY mr.created_at DESC`,
      [req.user.id, patientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get specific medical record
router.get('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.id = $1 AND mr.professional_id = $2`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new medical record
router.post('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      appointment_id,
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, client_id, dependent_id, appointment_id,
        chief_complaint, history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, appointment_id,
       chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update medical record
router.put('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
           treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
router.delete('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;