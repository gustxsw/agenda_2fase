import express from 'express';
import { pool } from '../db.js';
import { authenticate, authorize } from '../middleware/auth.js';
const router = express.Router();

// Get professional's private patients
router.get('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get specific private patient
router.get('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE id = $1 AND professional_id = $2`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new private patient
router.post('/', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name,
      cpf,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code
    } = req.body;

    // Check if CPF already exists for this professional
    const existingPatient = await pool.query(
      `SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2`,
      [cpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: 'Já existe um paciente cadastrado com este CPF' });
    }

    const result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, 
        address_number, address_complement, neighborhood, city, state, zip_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [req.user.id, name, cpf, email, phone, birth_date, address, 
       address_number, address_complement, neighborhood, city, state, zip_code]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update private patient
router.put('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code
    } = req.body;

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND professional_id = $13
       RETURNING *`,
      [name, email, phone, birth_date, address, address_number, address_complement,
       neighborhood, city, state, zip_code, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete private patient
router.delete('/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if patient has appointments
    const appointmentsCheck = await pool.query(
      `SELECT COUNT(*) FROM appointments WHERE private_patient_id = $1`,
      [id]
    );

    if (parseInt(appointmentsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir paciente que possui agendamentos' 
      });
    }

    const result = await pool.query(
      `DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Search private patients by CPF or name
router.get('/search/:query', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { query } = req.params;

    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       AND (name ILIKE $2 OR cpf LIKE $3)
       ORDER BY name
       LIMIT 10`,
      [req.user.id, `%${query}%`, `%${query.replace(/\D/g, '')}%`]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error searching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

export default router;