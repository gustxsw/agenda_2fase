import express from 'express';
import { pool } from '../db.js';
import { authenticate } from '../middleware/auth.js';
import { generatePDFFromHTML } from '../utils/pdfGenerator.js';
import { v2 as cloudinary } from 'cloudinary';

const router = express.Router();

// Save PDF document
router.post('/save', authenticate, async (req, res) => {
  try {
    const { title, document_type, patient_name, patient_cpf, pdf_data, document_metadata } = req.body;

    console.log('🔄 [PDF] Saving PDF document:', {
      title,
      document_type,
      patient_name,
      professional_id: req.user.id
    });

    // Validate required fields
    if (!title || !document_type || !patient_name || !pdf_data) {
      return res.status(400).json({ 
        message: 'Título, tipo de documento, nome do paciente e dados do PDF são obrigatórios' 
      });
    }

    // Validate base64 PDF data
    if (!pdf_data || typeof pdf_data !== 'string') {
      return res.status(400).json({ 
        message: 'Dados do PDF inválidos' 
      });
    }

    // Generate unique filename
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substr(2, 9);
    const fileName = `${document_type}_${timestamp}_${randomString}`;

    console.log('🔄 [PDF] Uploading PDF to Cloudinary...');

    // Upload PDF to Cloudinary
    const uploadResult = await cloudinary.uploader.upload(
      `data:application/pdf;base64,${pdf_data}`,
      {
        folder: 'quiro-ferreira/documents',
        resource_type: 'raw',
        format: 'pdf',
        public_id: fileName,
        use_filename: false,
        unique_filename: true
      }
    );

    console.log('✅ [PDF] PDF uploaded to Cloudinary:', uploadResult.secure_url);

    // Save document reference to database
    const result = await pool.query(`
      INSERT INTO saved_documents (
        title, document_type, patient_name, patient_cpf, 
        professional_id, document_url, document_metadata, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *
    `, [
      title,
      document_type,
      patient_name,
      patient_cpf || null,
      req.user.id,
      uploadResult.secure_url,
      JSON.stringify(document_metadata || {})
    ]);

    console.log('✅ [PDF] PDF document saved to database');

    res.json({
      message: 'Documento PDF salvo com sucesso',
      document: result.rows[0],
      document_url: uploadResult.secure_url
    });
  } catch (error) {
    console.error('❌ [PDF] Error saving PDF document:', error);
    res.status(500).json({ 
      message: error.message || 'Erro ao salvar documento PDF' 
    });
  }
});

// Get saved PDF documents for current professional
router.get('/saved', authenticate, async (req, res) => {
  try {
    console.log('🔄 [PDF] Fetching saved PDF documents for professional:', req.user.id);

    const result = await pool.query(`
      SELECT *
      FROM saved_documents
      WHERE professional_id = $1
      ORDER BY created_at DESC
    `, [req.user.id]);

    console.log('✅ [PDF] Saved PDF documents found:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ [PDF] Error fetching saved PDF documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos salvos' });
  }
});

// Delete saved PDF document
router.delete('/saved/:id', authenticate, async (req, res) => {
  try {
    const documentId = req.params.id;

    console.log('🔄 [PDF] Deleting saved PDF document:', documentId);

    // Get document info first
    const documentResult = await pool.query(
      'SELECT * FROM saved_documents WHERE id = $1 AND professional_id = $2',
      [documentId, req.user.id]
    );

    if (documentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Documento não encontrado' });
    }

    const document = documentResult.rows[0];

    // Delete from database
    await pool.query(
      'DELETE FROM saved_documents WHERE id = $1 AND professional_id = $2',
      [documentId, req.user.id]
    );

    console.log('✅ [PDF] Saved PDF document deleted from database');

    // Try to delete from Cloudinary (optional)
    try {
      if (document.document_url) {
        const urlParts = document.document_url.split('/');
        const publicIdWithExtension = urlParts[urlParts.length - 1];
        const publicId = publicIdWithExtension.split('.')[0];
        
        await cloudinary.uploader.destroy(`quiro-ferreira/documents/${publicId}`, {
          resource_type: 'raw'
        });
        console.log('✅ [PDF] PDF deleted from Cloudinary');
      }
    } catch (cloudinaryError) {
      console.warn('⚠️ [PDF] Could not delete PDF from Cloudinary:', cloudinaryError);
    }

    res.json({ message: 'Documento excluído com sucesso' });
  } catch (error) {
    console.error('❌ [PDF] Error deleting saved PDF document:', error);
    res.status(500).json({ message: 'Erro ao excluir documento' });
  }
});

export default router;