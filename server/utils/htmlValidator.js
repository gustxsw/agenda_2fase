// HTML Validation Utilities for Medical Documents

/**
 * Validates HTML content structure and completeness
 * @param {string} html - HTML content to validate
 * @param {string} documentType - Type of document being validated
 * @returns {Object} - Validation result with success status and details
 */
export const validateHTMLContent = (html, documentType = 'unknown') => {
  console.log('DEBUG Starting HTML validation for document type:', documentType);
  console.log('DEBUG HTML content length:', html ? html.length : 0);
  
  const validation = {
    isValid: false,
    errors: [],
    warnings: [],
    details: {
      hasDoctype: false,
      hasHtmlTags: false,
      hasHead: false,
      hasBody: false,
      hasTitle: false,
      hasContent: false,
      hasStyles: false,
      contentLength: 0
    }
  };
  
  try {
    // Basic existence check
    if (!html || typeof html !== 'string') {
      validation.errors.push('HTML content is null, undefined, or not a string');
      return validation;
    }
    
    const htmlLower = html.toLowerCase();
    validation.details.contentLength = html.length;
    
    // Check for minimum length
    if (html.length < 100) {
      validation.errors.push(`HTML content too short (${html.length} characters). Minimum expected: 100`);
      return validation;
    }
    
    // Check for DOCTYPE
    validation.details.hasDoctype = htmlLower.includes('<!doctype html>') || htmlLower.includes('<!doctype html');
    if (!validation.details.hasDoctype) {
      validation.warnings.push('Missing DOCTYPE declaration');
    }
    
    // Check for HTML tags
    validation.details.hasHtmlTags = htmlLower.includes('<html') && htmlLower.includes('</html>');
    if (!validation.details.hasHtmlTags) {
      validation.errors.push('Missing required HTML tags (<html> and </html>)');
    }
    
    // Check for HEAD section
    validation.details.hasHead = htmlLower.includes('<head>') && htmlLower.includes('</head>');
    if (!validation.details.hasHead) {
      validation.errors.push('Missing HEAD section');
    }
    
    // Check for BODY section
    validation.details.hasBody = htmlLower.includes('<body>') && htmlLower.includes('</body>');
    if (!validation.details.hasBody) {
      validation.errors.push('Missing BODY section');
    }
    
    // Check for TITLE
    validation.details.hasTitle = htmlLower.includes('<title>') && htmlLower.includes('</title>');
    if (!validation.details.hasTitle) {
      validation.warnings.push('Missing TITLE tag');
    }
    
    // Check for CSS styles
    validation.details.hasStyles = htmlLower.includes('<style>') || htmlLower.includes('style=');
    if (!validation.details.hasStyles) {
      validation.warnings.push('No CSS styles found - document may not render correctly');
    }
    
    // Check for meaningful content
    const bodyContent = extractBodyContent(html);
    validation.details.hasContent = bodyContent.length > 50;
    if (!validation.details.hasContent) {
      validation.errors.push('Body content appears to be empty or too short');
    }
    
    // Document-specific validations
    switch (documentType) {
      case 'certificate':
        validateCertificateContent(html, validation);
        break;
      case 'prescription':
        validatePrescriptionContent(html, validation);
        break;
      case 'medical_record':
        validateMedicalRecordContent(html, validation);
        break;
      case 'consent_form':
        validateConsentFormContent(html, validation);
        break;
      case 'exam_request':
        validateExamRequestContent(html, validation);
        break;
      default:
        validateGenericContent(html, validation);
    }
    
    // Determine overall validity
    validation.isValid = validation.errors.length === 0;
    
    console.log('DEBUG HTML validation completed');
    console.log('DEBUG Validation result:', {
      isValid: validation.isValid,
      errorCount: validation.errors.length,
      warningCount: validation.warnings.length
    });
    
    if (validation.errors.length > 0) {
      console.log('ERROR HTML validation errors:', validation.errors);
    }
    
    if (validation.warnings.length > 0) {
      console.log('WARNING HTML validation warnings:', validation.warnings);
    }
    
    return validation;
    
  } catch (error) {
    console.error('ERROR HTML validation process failed:', error.message);
    validation.errors.push(`Validation process failed: ${error.message}`);
    return validation;
  }
};

/**
 * Extract content from body tag
 */
const extractBodyContent = (html) => {
  try {
    const bodyMatch = html.match(/<body[^>]*>(.*?)<\/body>/is);
    if (bodyMatch && bodyMatch[1]) {
      // Remove HTML tags and get text content
      return bodyMatch[1].replace(/<[^>]*>/g, '').trim();
    }
    return '';
  } catch (error) {
    console.error('ERROR extracting body content:', error.message);
    return '';
  }
};

/**
 * Validate certificate-specific content
 */
const validateCertificateContent = (html, validation) => {
  const requiredElements = [
    { text: 'atestado', description: 'Certificate title' },
    { text: 'paciente', description: 'Patient information' },
    { text: 'dia', description: 'Days of leave' }
  ];
  
  const htmlLower = html.toLowerCase();
  
  requiredElements.forEach(element => {
    if (!htmlLower.includes(element.text)) {
      validation.warnings.push(`Certificate missing: ${element.description}`);
    }
  });
};

/**
 * Validate prescription-specific content
 */
const validatePrescriptionContent = (html, validation) => {
  const requiredElements = [
    { text: 'receitu', description: 'Prescription title' },
    { text: 'paciente', description: 'Patient information' }
  ];
  
  const htmlLower = html.toLowerCase();
  
  requiredElements.forEach(element => {
    if (!htmlLower.includes(element.text)) {
      validation.warnings.push(`Prescription missing: ${element.description}`);
    }
  });
};

/**
 * Validate medical record-specific content
 */
const validateMedicalRecordContent = (html, validation) => {
  const requiredElements = [
    { text: 'prontu', description: 'Medical record title' },
    { text: 'paciente', description: 'Patient information' }
  ];
  
  const htmlLower = html.toLowerCase();
  
  requiredElements.forEach(element => {
    if (!htmlLower.includes(element.text)) {
      validation.warnings.push(`Medical record missing: ${element.description}`);
    }
  });
};

/**
 * Validate consent form-specific content
 */
const validateConsentFormContent = (html, validation) => {
  const requiredElements = [
    { text: 'consentimento', description: 'Consent form title' },
    { text: 'procedimento', description: 'Procedure information' },
    { text: 'risco', description: 'Risk information' }
  ];
  
  const htmlLower = html.toLowerCase();
  
  requiredElements.forEach(element => {
    if (!htmlLower.includes(element.text)) {
      validation.warnings.push(`Consent form missing: ${element.description}`);
    }
  });
};

/**
 * Validate exam request-specific content
 */
const validateExamRequestContent = (html, validation) => {
  const requiredElements = [
    { text: 'exame', description: 'Exam request title' },
    { text: 'paciente', description: 'Patient information' }
  ];
  
  const htmlLower = html.toLowerCase();
  
  requiredElements.forEach(element => {
    if (!htmlLower.includes(element.text)) {
      validation.warnings.push(`Exam request missing: ${element.description}`);
    }
  });
};

/**
 * Validate generic document content
 */
const validateGenericContent = (html, validation) => {
  const htmlLower = html.toLowerCase();
  
  if (!htmlLower.includes('paciente')) {
    validation.warnings.push('Generic document missing patient information');
  }
};

/**
 * Generate a detailed validation report
 */
export const generateValidationReport = (validation) => {
  const report = {
    summary: validation.isValid ? 'VALID' : 'INVALID',
    contentLength: validation.details.contentLength,
    structure: {
      doctype: validation.details.hasDoctype ? 'OK' : 'MISSING',
      htmlTags: validation.details.hasHtmlTags ? 'OK' : 'MISSING',
      head: validation.details.hasHead ? 'OK' : 'MISSING',
      body: validation.details.hasBody ? 'OK' : 'MISSING',
      title: validation.details.hasTitle ? 'OK' : 'MISSING',
      content: validation.details.hasContent ? 'OK' : 'EMPTY',
      styles: validation.details.hasStyles ? 'OK' : 'MISSING'
    },
    issues: {
      errors: validation.errors,
      warnings: validation.warnings
    }
  };
  
  console.log('DEBUG Validation report generated:', JSON.stringify(report, null, 2));
  return report;
};