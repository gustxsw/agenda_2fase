const { pool } = require('../db.js');

const ensureSignatureColumn = async () => {
  try {
    console.log('🔍 Verificando se a coluna signature_url existe...');
    
    // Check if signature_url column exists
    const columnCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' 
      AND column_name = 'signature_url'
    `);
    
    if (columnCheck.rows.length === 0) {
      console.log('➕ Coluna signature_url não existe, criando...');
      
      // Add signature_url column
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN signature_url TEXT
      `);
      
      console.log('✅ Coluna signature_url criada com sucesso!');
    } else {
      console.log('✅ Coluna signature_url já existe');
    }
  } catch (error) {
    console.error('❌ Erro ao verificar/criar coluna signature_url:', error);
    // Don't throw error to prevent server startup failure
  }
};

module.exports = { ensureSignatureColumn };