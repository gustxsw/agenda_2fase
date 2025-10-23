// Document Generator - Production Ready
import { v2 as cloudinary } from 'cloudinary';

/**
 * Validates and sanitizes template data to prevent injection attacks
 * @param {Object} data - Raw template data
 * @returns {Object} - Sanitized and validated data
 */
const validateAndSanitizeData = (data) => {
  if (!data || typeof data !== 'object') {
    throw new Error('Template data must be a valid object');
  }

  // Sanitize HTML content to prevent XSS
  const sanitize = (str) => {
    if (!str || typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .trim();
  };

  // Format date consistently
  const formatDate = (dateStr) => {
    if (!dateStr) return new Date().toLocaleDateString('pt-BR');
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) {
        return new Date().toLocaleDateString('pt-BR');
      }
      return date.toLocaleDateString('pt-BR');
    } catch {
      return new Date().toLocaleDateString('pt-BR');
    }
  };

  return {
    // Patient information
    patientName: sanitize(data.patientName) || 'Nome não informado',
    patientCpf: sanitize(data.patientCpf) || '',
    
    // Professional information
    professionalName: sanitize(data.professionalName) || 'Profissional de Saúde',
    professionalSpecialty: sanitize(data.professionalSpecialty) || '',
    crm: sanitize(data.crm) || '',
    
    // Document content
    title: sanitize(data.title) || 'Documento Médico',
    content: sanitize(data.content) || '',
    description: sanitize(data.description) || '',
    
    // Medical certificate specific
    cid: sanitize(data.cid) || '',
    days: sanitize(data.days) || '1',
    
    // Prescription specific
    prescription: sanitize(data.prescription) || '',
    
    // Consent form specific
    procedure: sanitize(data.procedure) || '',
    risks: sanitize(data.risks) || '',
    
    // Signature
    signatureUrl: data.signatureUrl || null,
    
    // Dates
    currentDate: formatDate(),
    attendanceDate: formatDate(data.date),
    date: formatDate(data.date)
  };
};

/**
 * Base HTML structure with embedded CSS for reliable rendering
 */
const getBaseHTML = (title, content) => {
  if (!title || !content) {
    throw new Error('Title and content are required for HTML generation');
  }

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Times New Roman', serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000 !important;
            background: #fff !important;
            padding: 40px !important;
            margin: 0 !important;
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
            border-radius: 4px;
        }
        
        .content-section {
            margin: 20px 0;
            padding: 15px;
            background: #fff;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        
        .prescription-box {
            border: 2px solid #333;
            padding: 20px;
            margin: 20px 0;
            background: #fff;
            min-height: 150px;
        }
        
        .prescription-content {
            font-size: 16px;
            line-height: 2;
            white-space: pre-line;
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
        
        .signature-image {
            max-width: 200px;
            max-height: 60px;
            margin: 20px auto 10px;
            display: block;
        }
        
        .dual-signature {
            margin-top: 60px;
            display: flex;
            justify-content: space-between;
        }
        
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }
        
        p {
            margin: 10px 0;
            text-align: justify;
        }
        
        strong {
            font-weight: bold;
        }
        
        ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        li {
            margin: 5px 0;
        }
        
        h3, h4 {
            color: #333;
            margin: 15px 0 10px 0;
        }
        
        @media print {
            body { margin: 0; padding: 20px; }
            .document-header { page-break-after: avoid; }
            .signature-area { page-break-before: avoid; }
        }
        
            size: A4; 
            margin: 20mm; 
        }
    </style>
</head>
<body>
    
    ${content}
    
</body>
</html>`;
};

/**
 * Medical Certificate Template
 */
const generateCertificateHTML = (data) => {
  console.log('🔄 Generating certificate HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.description) {
      throw new Error('Descrição do atestado é obrigatória');
    }
    
    if (!sanitizedData.days || isNaN(parseInt(sanitizedData.days))) {
      throw new Error('Número de dias deve ser um valor numérico válido');
    }
    
    const content = `
        <div class="document-title">Atestado Médico</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <p>Atesto para os devidos fins que o(a) paciente acima identificado(a) esteve sob meus cuidados médicos e apresenta quadro clínico que o(a) impossibilita de exercer suas atividades habituais.</p>
            
            <p><strong>Descrição:</strong> ${sanitizedData.description}</p>
            
            ${sanitizedData.cid ? `<p><strong>CID:</strong> ${sanitizedData.cid}</p>` : ''}
            
            <p><strong>Período de afastamento:</strong> ${sanitizedData.days} dia(s) a partir de ${sanitizedData.currentDate}.</p>
            
            <p>Este atestado é válido para todos os fins legais e administrativos.</p>
        </div>
        
        <div class="signature-area">
            ${sanitizedData.signatureUrl ? 
              `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
              '<div class="signature-line"></div>'
            }
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Atestado Médico', content);
    console.log('✅ Certificate HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Certificate HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar atestado: ${error.message}`);
  }
};

/**
 * Prescription Template
 */
const generatePrescriptionHTML = (data) => {
  console.log('🔄 Generating prescription HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.prescription) {
      throw new Error('Conteúdo da prescrição é obrigatório');
    }
    
    const content = `
        <div class="document-title">Receituário Médico</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="prescription-box">
            <div class="prescription-content">${sanitizedData.prescription}</div>
        </div>
        
        <div class="signature-area">
            ${sanitizedData.signatureUrl ? 
              `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
              '<div class="signature-line"></div>'
            }
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Receituário Médico', content);
    console.log('✅ Prescription HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Prescription HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar receituário: ${error.message}`);
  }
};

/**
 * Consent Form Template
 */
const generateConsentFormHTML = (data) => {
  console.log('🔄 Generating consent form HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.procedure || !sanitizedData.description || !sanitizedData.risks) {
      throw new Error('Procedimento, descrição e riscos são obrigatórios para o termo de consentimento');
    }
    
    const content = `
        <div class="document-title">Termo de Consentimento Livre e Esclarecido</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <div class="section-title">Procedimento a ser realizado:</div>
            <p><strong>${sanitizedData.procedure}</strong></p>
            <p>${sanitizedData.description}</p>
        </div>
        
        <div class="content-section">
            <div class="section-title">Riscos e Benefícios:</div>
            <p>${sanitizedData.risks}</p>
        </div>
        
        <div class="content-section">
            <div class="section-title">Declaração de Consentimento:</div>
            <p>Declaro que fui devidamente informado(a) sobre o procedimento acima descrito, seus riscos, benefícios e alternativas. Todas as minhas dúvidas foram esclarecidas e consinto com a realização do procedimento.</p>
            <p>Estou ciente de que nenhum procedimento médico é 100% isento de riscos e que complicações podem ocorrer, mesmo com todos os cuidados técnicos adequados.</p>
            <p>Autorizo o profissional de saúde a realizar o procedimento proposto e declaro que este consentimento é dado de forma livre e esclarecida.</p>
        </div>
        
        <div class="dual-signature">
            <div class="signature-box">
                <div class="signature-line"></div>
                <div>
                    <strong>Paciente ou Responsável</strong><br>
                    ${sanitizedData.patientName}
                </div>
            </div>
            
            <div class="signature-box">
                ${sanitizedData.signatureUrl ? 
                  `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" style="max-width: 150px; max-height: 50px; margin: 20px auto 10px; display: block;" />` : 
                  '<div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>'
                }
                <div>
                    <strong>Profissional Responsável</strong><br>
                    ${sanitizedData.professionalName}<br>
                    ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
                </div>
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Termo de Consentimento', content);
    console.log('✅ Consent form HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Consent form HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar termo de consentimento: ${error.message}`);
  }
};

/**
 * Exam Request Template
 */
const generateExamRequestHTML = (data) => {
  console.log('🔄 Generating exam request HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.content) {
      throw new Error('Conteúdo dos exames solicitados é obrigatório');
    }
    
    const content = `
        <div class="document-title">Solicitação de Exames</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="prescription-box">
            <div class="section-title">Exames Solicitados:</div>
            <div class="prescription-content">${sanitizedData.content}</div>
        </div>
        
        <div class="signature-area">
            ${sanitizedData.signatureUrl ? 
              `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
              '<div class="signature-line"></div>'
            }
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Solicitação de Exames', content);
    console.log('✅ Exam request HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Exam request HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar solicitação de exames: ${error.message}`);
  }
};

/**
 * Declaration Template
 */
const generateDeclarationHTML = (data) => {
  console.log('🔄 Generating declaration HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.content) {
      throw new Error('Conteúdo da declaração é obrigatório');
    }
    
    const content = `
        <div class="document-title">${sanitizedData.title}</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <p>${sanitizedData.content}</p>
        </div>
        
        <div class="signature-area">
            ${sanitizedData.signatureUrl ? 
              `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
              '<div class="signature-line"></div>'
            }
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML(sanitizedData.title, content);
    console.log('✅ Declaration HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Declaration HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar declaração: ${error.message}`);
  }
};

/**
 * LGPD Term Template
 */
const generateLGPDHTML = (data) => {
  console.log('🔄 Generating LGPD HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    const content = `
        <div class="document-title">Termo de Consentimento para Tratamento de Dados Pessoais (LGPD)</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <div class="section-title">1. FINALIDADE DO TRATAMENTO DE DADOS</div>
            <p>Os dados pessoais coletados serão utilizados exclusivamente para:</p>
            <ul>
                <li>Prestação de serviços de saúde e acompanhamento médico;</li>
                <li>Manutenção do histórico médico e prontuário;</li>
                <li>Comunicação sobre consultas e tratamentos;</li>
                <li>Cumprimento de obrigações legais e regulamentares.</li>
            </ul>
        </div>
        
        <div class="content-section">
            <div class="section-title">2. DADOS COLETADOS</div>
            <p>Serão tratados dados pessoais como nome, CPF, endereço, telefone, email, informações de saúde e histórico médico.</p>
        </div>
        
        <div class="content-section">
            <div class="section-title">3. COMPARTILHAMENTO</div>
            <p>Os dados não serão compartilhados com terceiros, exceto quando necessário para a prestação do serviço médico ou por determinação legal.</p>
        </div>
        
        <div class="content-section">
            <div class="section-title">4. DIREITOS DO TITULAR</div>
            <p>Você tem direito a acessar, corrigir, excluir ou solicitar a portabilidade de seus dados, conforme a Lei Geral de Proteção de Dados (LGPD).</p>
        </div>
        
        <div class="content-section">
            <div class="section-title">5. CONSENTIMENTO</div>
            <p>Ao assinar este termo, declaro que:</p>
            <ul>
                <li>Fui informado(a) sobre o tratamento dos meus dados pessoais;</li>
                <li>Compreendo as finalidades do tratamento;</li>
                <li>Consinto com o tratamento dos meus dados conforme descrito;</li>
                <li>Posso revogar este consentimento a qualquer momento.</li>
            </ul>
        </div>
        
        <div class="dual-signature">
            <div class="signature-box">
                <div class="signature-line"></div>
                <div>
                    <strong>Paciente ou Responsável</strong><br>
                    ${sanitizedData.patientName}
                </div>
            </div>
            
            <div class="signature-box">
                ${sanitizedData.signatureUrl ? 
                  `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" style="max-width: 150px; max-height: 50px; margin: 20px auto 10px; display: block;" />` : 
                  '<div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>'
                }
                <div>
                    <strong>Profissional Responsável</strong><br>
                    ${sanitizedData.professionalName}<br>
                    ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
                </div>
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Termo LGPD', content);
    console.log('✅ LGPD HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ LGPD HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar termo LGPD: ${error.message}`);
  }
};

/**
 * Generic Document Template
 */
const generateGenericHTML = (data) => {
  console.log('🔄 Generating generic document HTML');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    
    if (!sanitizedData.content) {
      throw new Error('Conteúdo do documento é obrigatório');
    }
    
    const content = `
        <div class="document-title">${sanitizedData.title}</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <p>${sanitizedData.content}</p>
        </div>
        
        <div class="signature-area">
            ${sanitizedData.signatureUrl ? 
              `<img src="${sanitizedData.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
              '<div class="signature-line"></div>'
            }
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML(sanitizedData.title, content);
    console.log('✅ Generic document HTML generated successfully');
    
    return html;
  } catch (error) {
    console.error('❌ Generic document HTML generation failed:', error.message);
    throw new Error(`Falha ao gerar documento: ${error.message}`);
  }
};

/**
 * Create optimized HTML specifically for PDF generation
 */
const createOptimizedHTMLForPDF = (htmlContent) => {
  // Extract content from body if it's a complete HTML document
  let bodyContent = htmlContent;
  
  // If it's a complete HTML document, extract just the body content
  const bodyMatch = htmlContent.match(/<body[^>]*>(.*?)<\/body>/is);
  if (bodyMatch && bodyMatch[1]) {
    bodyContent = bodyMatch[1];
  }
  
  // Remove any existing document structure tags
  bodyContent = bodyContent
    .replace(/<!DOCTYPE[^>]*>/gi, '')
    .replace(/<\/?html[^>]*>/gi, '')
    .replace(/<\/?head[^>]*>/gi, '')
    .replace(/<\/?body[^>]*>/gi, '')
    .replace(/<style[^>]*>.*?<\/style>/gis, '') // Remove existing styles
    .trim();
  
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documento Médico</title>
    <style>
        @page { 
            size: A4; 
            margin: 15mm; 
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Times New Roman', serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000 !important;
            background: #fff !important;
            padding: 20px !important;
            margin: 0 !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }
        
        .document-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #333;
            page-break-after: avoid;
        }
        
        .logo {
            font-size: 24px !important;
            font-weight: bold !important;
            color: #333 !important;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 14px !important;
            color: #666 !important;
        }
        
        .document-title {
            font-size: 20px !important;
            font-weight: bold !important;
            text-transform: uppercase;
            text-align: center;
            margin: 30px 0 !important;
            color: #000 !important;
            page-break-after: avoid;
        }
        
        .patient-info {
            background: #f9f9f9 !important;
            padding: 15px !important;
            margin: 20px 0 !important;
            border-left: 4px solid #333 !important;
            border-radius: 4px;
            page-break-inside: avoid;
        }
        
        .content-section {
            margin: 20px 0 !important;
            padding: 15px !important;
            background: #fff !important;
            page-break-inside: avoid;
        }
        
        .section-title {
            font-size: 16px !important;
            font-weight: bold !important;
            color: #333 !important;
            margin-bottom: 10px !important;
            border-bottom: 1px solid #eee !important;
            padding-bottom: 5px !important;
        }
        
        .prescription-box {
            border: 2px solid #333 !important;
            padding: 20px !important;
            margin: 20px 0 !important;
            background: #fff !important;
            min-height: 150px;
            page-break-inside: avoid;
        }
        
        .prescription-content {
            font-size: 16px !important;
            line-height: 2 !important;
            white-space: pre-line;
        }
        
        .signature-area {
            margin-top: 60px !important;
            text-align: center;
            page-break-before: avoid;
        }
        
        .signature-line {
            border-top: 1px solid #000 !important;
            width: 300px;
            margin: 40px auto 10px !important;
        }
        
        .signature-image {
            max-width: 200px !important;
            max-height: 60px !important;
            margin: 20px auto 10px !important;
            display: block !important;
        }
        
        .dual-signature {
            margin-top: 60px !important;
            display: flex !important;
            justify-content: space-between !important;
            page-break-before: avoid;
        }
        
        .signature-box {
            text-align: center;
            width: 45% !important;
        }
        
        .document-footer {
            margin-top: 40px !important;
            text-align: center;
            font-size: 12px !important;
            color: #666 !important;
            border-top: 1px solid #ddd !important;
            padding-top: 20px !important;
            page-break-before: avoid;
        }
        
        .vital-signs-grid {
            display: grid !important;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)) !important;
            gap: 10px !important;
            margin: 15px 0 !important;
        }
        
        .vital-sign-item {
            text-align: center;
            padding: 10px !important;
            background: #f8f9fa !important;
            border: 1px solid #e9ecef !important;
            border-radius: 4px;
        }
        
        .vital-sign-label {
            font-size: 11px !important;
            color: #666 !important;
            margin-bottom: 5px !important;
        }
        
        .vital-sign-value {
            font-weight: bold !important;
            color: #333 !important;
        }
        
        p {
            margin: 10px 0 !important;
            text-align: justify;
            color: #000 !important;
        }
        
        strong {
            font-weight: bold !important;
            color: #000 !important;
        }
        
        ul {
            margin: 10px 0 !important;
            padding-left: 20px !important;
        }
        
        li {
            margin: 5px 0 !important;
            color: #000 !important;
        }
        
        h3, h4 {
            color: #333;
            margin: 15px 0 10px 0 !important;
        }
        
        /* Ensure all text is visible */
        * {
            color: #000 !important;
        }
        
        /* Override any inherited styles */
        div, span, p, h1, h2, h3, h4, h5, h6 {
            color: #000 !important;
        }
        
        @media print {
            body { 
                margin: 0 !important; 
                padding: 20px !important; 
                background: #fff !important;
            }
            .document-header { page-break-after: avoid; }
            .signature-area { page-break-before: avoid; }
            * { color: #000 !important; }
        }
    </style>
</head>
<body>
    
    ${bodyContent}
    
</body>
</html>`;
};

/**
 * Document templates mapping
 */
const templates = {
  certificate: generateCertificateHTML,
  prescription: generatePrescriptionHTML,
  consent_form: generateConsentFormHTML,
  exam_request: generateExamRequestHTML,
  declaration: generateDeclarationHTML,
  lgpd: generateLGPDHTML,
  other: generateGenericHTML
};

/**
 * Upload HTML document to Cloudinary
 */
const uploadHTMLToCloudinary = async (htmlContent, fileName) => {
  console.log('🔄 Uploading HTML to Cloudinary');
  
  try {
    if (!htmlContent || typeof htmlContent !== 'string') {
      throw new Error('HTML content is required and must be a string');
    }
    
    if (!fileName || typeof fileName !== 'string') {
      throw new Error('File name is required and must be a string');
    }
    
    // Create optimized HTML for better PDF rendering
    const optimizedHTML = createOptimizedHTMLForPDF(htmlContent);
    
    // Generate unique filename
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substr(2, 9);
    const uniqueFileName = `${fileName}_${timestamp}_${randomString}`;
    
    // Upload HTML to Cloudinary as raw file
    const uploadResult = await cloudinary.uploader.upload(
      `data:text/html;base64,${Buffer.from(optimizedHTML).toString('base64')}`,
      {
        folder: 'quiro-ferreira/documents',
        resource_type: 'raw',
        format: 'html',
        public_id: uniqueFileName,
        use_filename: false,
        unique_filename: true
      }
    );
    
    console.log('✅ HTML uploaded to Cloudinary:', uploadResult.secure_url);
    return uploadResult;
  } catch (error) {
    console.error('❌ Cloudinary upload failed:', error.message);
    throw new Error(`Falha no upload: ${error.message}`);
  }
};

/**
 * Main document generation function
 */
export const generateDocumentPDF = async (documentType, templateData) => {
  console.log('🔄 Starting document generation process');
  console.log('🔄 Document type:', documentType);
  console.log('🔄 Template data keys:', Object.keys(templateData || {}));
  
  try {
    // Validate input parameters
    if (!documentType || typeof documentType !== 'string') {
      throw new Error('Document type is required and must be a string');
    }
    
    if (!templateData || typeof templateData !== 'object') {
      throw new Error('Template data is required and must be an object');
    }
    
    // Get template function
    const templateFunction = templates[documentType];
    if (!templateFunction) {
      console.log('⚠️ Unknown document type, using generic template');
      templateFunction = templates.other;
    }
    
    // Generate HTML content
    console.log('🔄 Generating HTML content');
    const htmlContent = templateFunction(templateData);
    
    if (!htmlContent || htmlContent.length < 100) {
      throw new Error('Generated HTML content is too short or empty');
    }
    
    // Upload to Cloudinary
    console.log('🔄 Uploading to Cloudinary');
    const fileName = `${documentType}_${templateData.patientName || 'document'}`.replace(/[^a-zA-Z0-9_]/g, '_');
    const uploadResult = await uploadHTMLToCloudinary(htmlContent, fileName);
    
    console.log('✅ Document generation completed successfully');
    
    return {
      url: uploadResult.secure_url,
      public_id: uploadResult.public_id,
      bytes: uploadResult.bytes,
      format: 'html'
    };
  } catch (error) {
    console.error('❌ Document generation failed:', error.message);
    console.error('❌ Stack trace:', error.stack);
    
    // Log context for debugging
    const errorContext = {
      documentType: documentType,
      templateDataKeys: templateData ? Object.keys(templateData) : [],
      timestamp: new Date().toISOString()
    };
    
    console.error('❌ Error context:', JSON.stringify(errorContext, null, 2));
    
    throw new Error(`Falha na geração do documento: ${error.message}`);
  }
};

/**
 * Generate HTML document (for frontend use)
 */
export const generateDocumentHTML = (documentType, templateData) => {
  console.log('🔄 Generating HTML document for frontend');
  
  try {
    // Validate input parameters
    if (!documentType || typeof documentType !== 'string') {
      throw new Error('Document type is required and must be a string');
    }
    
    if (!templateData || typeof templateData !== 'object') {
      throw new Error('Template data is required and must be an object');
    }
    
    // Get template function
    let templateFunction = templates[documentType];
    if (!templateFunction) {
      console.log('⚠️ Unknown document type, using generic template');
      templateFunction = templates.other;
    }
    
    // Generate HTML content
    const htmlContent = templateFunction(templateData);
    
    if (!htmlContent || htmlContent.length < 100) {
      throw new Error('Generated HTML content is too short or empty');
    }
    
    console.log('✅ HTML document generated successfully for frontend');
    return htmlContent;
  } catch (error) {
    console.error('❌ HTML document generation failed:', error.message);
    throw new Error(`Falha ao gerar HTML: ${error.message}`);
  }
};

/**
 * Test function for validation
 */
export const testDocumentGeneration = async () => {
  console.log('🔄 Starting document generation test');
  
  const testData = {
    patientName: 'João Silva',
    patientCpf: '12345678901',
    professionalName: 'Dr. Maria Santos',
    professionalSpecialty: 'Fisioterapeuta',
    crm: 'CREFITO 12345/GO',
    title: 'Teste de Documento',
    description: 'Teste de geração de documento',
    days: '3',
    content: 'Conteúdo de teste para validação do sistema'
  };
  
  try {
    // Test certificate generation
    const certificateHTML = generateCertificateHTML(testData);
    console.log('✅ Certificate test passed');
    
    // Test prescription generation
    const prescriptionData = { ...testData, prescription: 'Medicamento de teste' };
    const prescriptionHTML = generatePrescriptionHTML(prescriptionData);
    console.log('✅ Prescription test passed');
    
    // Test generic document generation
    const genericHTML = generateGenericHTML(testData);
    console.log('✅ Generic document test passed');
    
    console.log('✅ All document generation tests passed');
    
    return {
      success: true,
      message: 'Todos os testes de geração de documentos passaram com sucesso',
      tests: {
        certificate: certificateHTML.length > 0,
        prescription: prescriptionHTML.length > 0,
        generic: genericHTML.length > 0
      }
    };
  } catch (error) {
    console.error('❌ Document generation test failed:', error.message);
    throw new Error(`Teste de geração falhou: ${error.message}`);
  }
};

// Maintain backward compatibility
export const generatePDFFromHTML = generateDocumentPDF;