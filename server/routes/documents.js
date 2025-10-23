import express from 'express';
import { pool } from '../db.js';
import { authenticate } from '../middleware/auth.js';
import { generateDocumentPDF } from '../utils/documentGenerator.js';
import { v2 as cloudinary } from 'cloudinary';

const router = express.Router();

// Get medical documents for current professional
router.get('/medical', authenticate, async (req, res) => {
  try {
    console.log('🔄 [DOCUMENTS] Fetching medical documents for professional:', req.user.id);

    // First try medical_documents table
    // First try medical_documents table
    let result = await pool.query(`
      SELECT 
        md.*,
        COALESCE(pp.name, md.patient_name) as patient_name,
        COALESCE(pp.cpf, md.patient_cpf) as patient_cpf
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    // If no results, also check saved_documents table
    if (result.rows.length === 0) {
      console.log('🔄 [DOCUMENTS] No medical documents found, checking saved_documents...');
      
      const savedResult = await pool.query(`
        SELECT 
          id,
          title,
          document_type,
          patient_name,
          patient_cpf,
          document_url,
          created_at
        FROM saved_documents
        WHERE professional_id = $1
        ORDER BY created_at DESC
      `, [req.user.id]);
      
      result = savedResult;
      console.log('✅ [DOCUMENTS] Found saved documents:', savedResult.rows.length);
    }

    // If no results, also check saved_documents table
    if (result.rows.length === 0) {
      console.log('🔄 [DOCUMENTS] No medical documents found, checking saved_documents...');
      
      const savedResult = await pool.query(`
        SELECT 
          id,
          title,
          document_type,
          patient_name,
          patient_cpf,
          document_url,
          created_at
        FROM saved_documents
        WHERE professional_id = $1
        ORDER BY created_at DESC
      `, [req.user.id]);
      
      result = savedResult;
      console.log('✅ [DOCUMENTS] Found saved documents:', savedResult.rows.length);
    }

    console.log('✅ [DOCUMENTS] Medical documents found:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos médicos' });
  }
});

// Create medical document
router.post('/medical', authenticate, async (req, res) => {
  try {
    const { title, document_type, private_patient_id, patient_name, patient_cpf, template_data } = req.body;

    console.log('🔄 [DOCUMENTS] Creating medical document:', {
      title,
      document_type,
      private_patient_id,
      patient_name,
      patient_cpf,
      professional_id: req.user.id
    });

    // Validate required fields
    if (!title || !document_type || !template_data) {
      return res.status(400).json({ 
        message: 'Título, tipo de documento e dados do template são obrigatórios' 
      });
    }

    // Validate patient data - either private_patient_id OR patient_name is required
    if (!private_patient_id && !patient_name) {
      return res.status(400).json({ 
        message: 'É necessário informar um paciente particular ou dados do paciente do convênio' 
      });
    }

    // Generate document using existing generator
    const documentResult = await generateDocumentPDF(document_type, template_data);
    
    console.log('✅ [DOCUMENTS] Document generated:', documentResult.url);

    // Save to database
    const result = await pool.query(`
      INSERT INTO medical_documents (
        title, document_type, private_patient_id, professional_id, 
        document_url, template_data, patient_name, patient_cpf, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING *
    `, [
      title,
      document_type,
      private_patient_id,
      req.user.id,
      documentResult.url,
      JSON.stringify(template_data),
      patient_name,
      patient_cpf
    ]);

    console.log('✅ [DOCUMENTS] Medical document saved to database');

    res.json({
      message: 'Documento médico criado com sucesso',
      document: result.rows[0],
      title: title,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error creating medical document:', error);
    res.status(500).json({ 
      message: error.message || 'Erro ao criar documento médico' 
    });
  }
});

// Delete medical document
router.delete('/medical/:id', authenticate, async (req, res) => {
  try {
    const documentId = req.params.id;

    console.log('🔄 [DOCUMENTS] Deleting medical document:', documentId);

    // Get document info first
    const documentResult = await pool.query(
      'SELECT * FROM medical_documents WHERE id = $1 AND professional_id = $2',
      [documentId, req.user.id]
    );

    if (documentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Documento não encontrado' });
    }

    const document = documentResult.rows[0];

    // Delete from database
    await pool.query(
      'DELETE FROM medical_documents WHERE id = $1 AND professional_id = $2',
      [documentId, req.user.id]
    );

    console.log('✅ [DOCUMENTS] Medical document deleted from database');

    // Try to delete from Cloudinary (optional, don't fail if it doesn't work)
    try {
      if (document.document_url) {
        const publicId = document.document_url.split('/').pop()?.split('.')[0];
        if (publicId) {
          await cloudinary.uploader.destroy(`quiro-ferreira/documents/${publicId}`, {
            resource_type: 'raw'
          });
          console.log('✅ [DOCUMENTS] Document deleted from Cloudinary');
        }
      }
    } catch (cloudinaryError) {
      console.warn('⚠️ [DOCUMENTS] Could not delete from Cloudinary:', cloudinaryError);
      // Don't fail the request if Cloudinary deletion fails
    }

    res.json({ message: 'Documento excluído com sucesso' });
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error deleting medical document:', error);
    res.status(500).json({ message: 'Erro ao excluir documento médico' });
  }
});

// NEW ROUTE: Save PDF document
router.post('/save', authenticate, async (req, res) => {
  try {
    const { title, document_type, patient_name, patient_cpf, pdf_data, document_metadata } = req.body;

    console.log('🔄 [DOCUMENTS] Saving PDF document:', {
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

    console.log('🔄 [DOCUMENTS] Uploading PDF to Cloudinary...');

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

    console.log('✅ [DOCUMENTS] PDF uploaded to Cloudinary:', uploadResult.secure_url);

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

    console.log('✅ [DOCUMENTS] PDF document saved to database');

    res.json({
      message: 'Documento PDF salvo com sucesso',
      document: result.rows[0],
      document_url: uploadResult.secure_url
    });
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error saving PDF document:', error);
    res.status(500).json({ 
      message: error.message || 'Erro ao salvar documento PDF' 
    });
  }
});

// Get saved PDF documents for current professional
router.get('/saved', authenticate, async (req, res) => {
  try {
    console.log('🔄 [DOCUMENTS] Fetching saved PDF documents for professional:', req.user.id);

    const result = await pool.query(`
      SELECT *
      FROM saved_documents
      WHERE professional_id = $1
      ORDER BY created_at DESC
    `, [req.user.id]);

    console.log('✅ [DOCUMENTS] Saved PDF documents found:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error fetching saved PDF documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos salvos' });
  }
});

// Delete saved PDF document
router.delete('/saved/:id', authenticate, async (req, res) => {
  try {
    const documentId = req.params.id;

    console.log('🔄 [DOCUMENTS] Deleting saved PDF document:', documentId);

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

    console.log('✅ [DOCUMENTS] Saved PDF document deleted from database');

    // Try to delete from Cloudinary (optional)
    try {
      if (document.document_url) {
        const urlParts = document.document_url.split('/');
        const publicIdWithExtension = urlParts[urlParts.length - 1];
        const publicId = publicIdWithExtension.split('.')[0];
        
        await cloudinary.uploader.destroy(`quiro-ferreira/documents/${publicId}`, {
          resource_type: 'raw'
        });
        console.log('✅ [DOCUMENTS] PDF deleted from Cloudinary');
      }
    } catch (cloudinaryError) {
      console.warn('⚠️ [DOCUMENTS] Could not delete PDF from Cloudinary:', cloudinaryError);
    }

    res.json({ message: 'Documento excluído com sucesso' });
  } catch (error) {
    console.error('❌ [DOCUMENTS] Error deleting saved PDF document:', error);
    res.status(500).json({ message: 'Erro ao excluir documento' });
  }
});

export default router;