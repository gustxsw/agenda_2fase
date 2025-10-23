// PDF generation using html2pdf.js approach for better compatibility
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { validateHTMLContent, generateValidationReport } from './htmlValidator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Simple PDF generation using base64 conversion for WebContainer compatibility
 */
const createOptimizedHTML = (htmlContent) => {
  // Enhanced HTML with better CSS for PDF generation
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        @page { size: A4; margin: 20mm; }
        body { 
            font-family: Arial, sans-serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000 !important;
            background: #fff !important;
            margin: 0 !important;
            padding: 20px !important;
        }
        .document-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #c11c22;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #c11c22;
            margin-bottom: 10px;
        }
        .document-title {
            font-size: 20px;
            font-weight: bold;
            text-transform: uppercase;
            text-align: center;
            margin: 30px 0;
            color: #000;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            margin: 20px 0;
            border-left: 4px solid #333;
        }
        .signature-area {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #000;
            width: 300px;
            margin: 40px auto 10px;
        }
    </style>
</head>
<body>
    ${htmlContent.replace(/^.*<body[^>]*>|<\/body>.*$/gi, '').replace(/^.*<!DOCTYPE[^>]*>|<\/html>.*$/gi, '')}
</body>
</html>`;
};

/**
 * Ensures temp directory exists and is writable
 */
const ensureTempDirectory = () => {
  const tempDir = path.join(__dirname, '../../temp');
  
  try {
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
      console.log('DEBUG Created temp directory:', tempDir);
    }
    
    // Test write permissions
    const testFile = path.join(tempDir, 'test_write.tmp');
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    
    console.log('DEBUG Temp directory verified and writable:', tempDir);
    return tempDir;
  } catch (error) {
    console.error('ERROR Temp directory setup failed:', error.message);
    throw new Error(`Cannot create or write to temp directory: ${error.message}`);
  }
};

/**
 * Simplified approach: Convert HTML to base64 and upload directly to Cloudinary
 */
const uploadHTMLToCloudinary = async (htmlContent, fileName) => {
  console.log('DEBUG Uploading HTML to Cloudinary as document');
  
  try {
    const optimizedHTML = createOptimizedHTML(htmlContent);
    
    // Upload HTML to Cloudinary as raw file
    const uploadResult = await cloudinary.uploader.upload(
      `data:text/html;base64,${Buffer.from(optimizedHTML).toString('base64')}`,
      {
        folder: 'quiro-ferreira/documents',
        resource_type: 'raw',
        format: 'html',
        public_id: `${fileName}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        use_filename: false,
        unique_filename: true
      }
    );
    
    console.log('SUCCESS HTML uploaded to Cloudinary:', uploadResult.secure_url);
    return uploadResult;
  } catch (error) {
    console.error('ERROR Uploading HTML to Cloudinary:', error.message);
    throw new Error(`Failed to upload HTML: ${error.message}`);
  }
};


/**
 * Simplified document generation - uploads HTML to Cloudinary for frontend PDF conversion
 */
export const generateDocumentFromHTML = async (htmlContent, fileName = 'document') => {
  console.log('DEBUG Starting document generation process');
  console.log('DEBUG Input file name:', fileName);
  console.log('DEBUG Input HTML length:', htmlContent ? htmlContent.length : 0);
  
  try {
    // Validate input parameters
    if (!htmlContent || typeof htmlContent !== 'string') {
      throw new Error('HTML content is required and must be a string');
    }
    
    if (!fileName || typeof fileName !== 'string') {
      throw new Error('File name is required and must be a string');
    }
    
    // Validate HTML content structure
    console.log('DEBUG Step 2: Validating HTML content structure');
    const validation = validateHTMLContent(htmlContent, 'medical_document');
    const validationReport = generateValidationReport(validation);
    
    console.log('DEBUG HTML validation report:', validationReport);
    
    // Upload HTML to Cloudinary
    console.log('DEBUG Step 3: Uploading HTML to Cloudinary');
    const uploadResult = await uploadHTMLToCloudinary(htmlContent, fileName);
    
    console.log('SUCCESS Document generation process completed successfully');
    
    return {
      url: uploadResult.secure_url,
      public_id: uploadResult.public_id,
      bytes: uploadResult.bytes,
      validation: validationReport
    };
  } catch (error) {
    console.error('ERROR Document generation process failed:', error.message);
    console.error('ERROR Stack trace:', error.stack);
    
    const errorContext = {
      step: 'unknown',
      htmlLength: htmlContent ? htmlContent.length : 0,
      fileName: fileName,
      tempFile: tempFilePath,
      timestamp: new Date().toISOString()
    };
    
    if (error.message.includes('HTML validation failed')) {
      errorContext.step = 'html_validation';
    } else if (error.message.includes('HTML upload')) {
      errorContext.step = 'temp_file_creation';
    } else if (error.message.includes('PDF buffer')) {
      errorContext.step = 'pdf_buffer_validation';
    } else if (error.message.includes('Cloudinary')) {
      errorContext.step = 'cloudinary_upload';
    } else {
      errorContext.step = 'pdf_generation';
    }
    
    console.error('ERROR Context:', JSON.stringify(errorContext, null, 2));
    
    throw new Error(`Document generation failed at ${errorContext.step}: ${error.message}`);
  }
};

// Maintain backward compatibility
export const generatePDFFromHTML = generateDocumentFromHTML;

/**
 * Test function to validate the document generation pipeline
 */
export const testDocumentGeneration = async () => {
  console.log('DEBUG Starting document generation test');
  
  const testHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Test Document</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { color: #c11c22; }
    </style>
</head>
<body>
    <h1>Test Document</h1>
    <p>This is a test document for PDF generation validation.</p>
    <p>Generated at: ${new Date().toLocaleString('pt-BR')}</p>
</body>
</html>`;

  try {
    const result = await generateDocumentFromHTML(testHTML, 'test_document');
    console.log('SUCCESS Document generation test passed:', result.url);
    return result;
  } catch (error) {
    console.error('ERROR Document generation test failed:', error.message);
    throw error;
  }
};

// Maintain backward compatibility
export const testPDFGeneration = testDocumentGeneration;