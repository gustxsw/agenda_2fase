// HTML Templates for Medical Documents
// Each template is a pure function that generates complete, valid HTML

/**
 * Validates and sanitizes template data
 * @param {Object} data - Raw template data
 * @returns {Object} - Sanitized and validated data
 */
const validateAndSanitizeData = (data) => {
  if (!data || typeof data !== 'object') {
    throw new Error('Template data must be a valid object');
  }

  // Sanitize HTML content to prevent injection
  const sanitize = (str) => {
    if (!str || typeof str !== 'string') return '';
    return str
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
      return new Date(dateStr).toLocaleDateString('pt-BR');
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
    
    // Medical record specific
    chief_complaint: sanitize(data.chief_complaint) || '',
    history_present_illness: sanitize(data.history_present_illness) || '',
    past_medical_history: sanitize(data.past_medical_history) || '',
    medications: sanitize(data.medications) || '',
    allergies: sanitize(data.allergies) || '',
    physical_examination: sanitize(data.physical_examination) || '',
    diagnosis: sanitize(data.diagnosis) || '',
    treatment_plan: sanitize(data.treatment_plan) || '',
    notes: sanitize(data.notes) || '',
    vital_signs: data.vital_signs || {},
    
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
            font-family: Arial, sans-serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000 !important;
            background: #fff !important;
            padding: 40px !important;
            margin: 0 !important;
        }
        
        .document-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #333;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 14px;
            color: #666;
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
        
        .signature-area {
            margin-top: 60px;
            text-align: center;
        }
        
        .signature-line {
            border-top: 1px solid #000;
            width: 300px;
            margin: 40px auto 10px;
        }
        
        .document-footer {
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }
        
        .vital-signs-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .vital-sign-item {
            text-align: center;
            padding: 10px;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
        }
        
        .vital-sign-label {
            font-size: 11px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .vital-sign-value {
            font-weight: bold;
            color: #333;
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
        
        @media print {
            body { margin: 0; padding: 20px; }
            .document-header { page-break-after: avoid; }
            .signature-area { page-break-before: avoid; }
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
export const generateCertificateHTML = (data) => {
  console.log('DEBUG Starting certificate HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Certificate data validated successfully');
    
    const content = `
        <div class="document-title">Atestado Médico</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        <div class="content-section">
            <p>Atesto para os devidos fins que o(a) paciente acima identificado(a) esteve sob meus cuidados médicos e apresenta quadro clínico que o(a) impossibilita de exercer suas atividades habituais.</p>
            
            ${sanitizedData.description ? `<p><strong>Descrição:</strong> ${sanitizedData.description}</p>` : ''}
            
            ${sanitizedData.cid ? `<p><strong>CID:</strong> ${sanitizedData.cid}</p>` : ''}
            
            <p><strong>Período de afastamento:</strong> ${sanitizedData.days} dia(s) a partir de ${sanitizedData.currentDate}.</p>
            
            <p>Este atestado é válido para todos os fins legais e administrativos.</p>
        </div>
        
        <div class="signature-area">
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Atestado Médico', content);
    console.log('SUCCESS Certificate HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Certificate HTML generation failed:', error.message);
    throw new Error(`Failed to generate certificate HTML: ${error.message}`);
  }
};

/**
 * Prescription Template
 */
export const generatePrescriptionHTML = (data) => {
  console.log('DEBUG Starting prescription HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Prescription data validated successfully');
    
    if (!sanitizedData.prescription) {
      throw new Error('Prescription content is required');
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
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Receituário Médico', content);
    console.log('SUCCESS Prescription HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Prescription HTML generation failed:', error.message);
    throw new Error(`Failed to generate prescription HTML: ${error.message}`);
  }
};

/**
 * Medical Record Template
 */
export const generateMedicalRecordHTML = (data) => {
  console.log('DEBUG Starting medical record HTML generation');
  console.log('DEBUG Input data keys:', Object.keys(data || {}));
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Medical record data validated successfully');
    
    // Build vital signs section
    const vitalSigns = sanitizedData.vital_signs || {};
    const hasVitalSigns = Object.values(vitalSigns).some(value => value && value.toString().trim());
    
    let vitalSignsHTML = '';
    if (hasVitalSigns) {
      const vitalSignItems = [
        { label: 'Pressão Arterial', value: vitalSigns.blood_pressure },
        { label: 'Freq. Cardíaca', value: vitalSigns.heart_rate },
        { label: 'Temperatura', value: vitalSigns.temperature },
        { label: 'Freq. Respiratória', value: vitalSigns.respiratory_rate },
        { label: 'Sat. O₂', value: vitalSigns.oxygen_saturation },
        { label: 'Peso', value: vitalSigns.weight },
        { label: 'Altura', value: vitalSigns.height }
      ].filter(item => item.value && item.value.toString().trim());
      
      if (vitalSignItems.length > 0) {
        vitalSignsHTML = `
            <div class="content-section">
                <div class="section-title">Sinais Vitais</div>
                <div class="vital-signs-grid">
                    ${vitalSignItems.map(item => `
                        <div class="vital-sign-item">
                            <div class="vital-sign-label">${item.label}</div>
                            <div class="vital-sign-value">${item.value}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
      }
    }
    
    // Build medical sections
    const medicalSections = [
      { title: 'Queixa Principal', content: sanitizedData.chief_complaint },
      { title: 'História da Doença Atual', content: sanitizedData.history_present_illness },
      { title: 'História Médica Pregressa', content: sanitizedData.past_medical_history },
      { title: 'Medicamentos em Uso', content: sanitizedData.medications },
      { title: 'Alergias', content: sanitizedData.allergies },
      { title: 'Exame Físico', content: sanitizedData.physical_examination },
      { title: 'Diagnóstico', content: sanitizedData.diagnosis },
      { title: 'Plano de Tratamento', content: sanitizedData.treatment_plan },
      { title: 'Observações Gerais', content: sanitizedData.notes }
    ].filter(section => section.content && section.content.trim());
    
    const medicalSectionsHTML = medicalSections.map(section => `
        <div class="content-section">
            <div class="section-title">${section.title}</div>
            <p>${section.content}</p>
        </div>
    `).join('');
    
    const content = `
        <div class="document-title">Prontuário Médico</div>
        
        <div class="patient-info">
            <strong>Paciente:</strong> ${sanitizedData.patientName}<br>
            ${sanitizedData.patientCpf ? `<strong>CPF:</strong> ${sanitizedData.patientCpf}<br>` : ''}
            <strong>Data do Atendimento:</strong> ${sanitizedData.attendanceDate}<br>
            <strong>Data de Emissão:</strong> ${sanitizedData.currentDate}
        </div>
        
        ${vitalSignsHTML}
        
        ${medicalSectionsHTML}
        
        ${medicalSections.length === 0 ? `
        <div class="content-section">
            <p><em>Prontuário médico sem informações clínicas detalhadas registradas.</em></p>
        </div>
        ` : ''}
        
        <div class="signature-area">
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Prontuário Médico', content);
    console.log('SUCCESS Medical record HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Medical record HTML generation failed:', error.message);
    throw new Error(`Failed to generate medical record HTML: ${error.message}`);
  }
};

/**
 * Consent Form Template
 */
export const generateConsentFormHTML = (data) => {
  console.log('DEBUG Starting consent form HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Consent form data validated successfully');
    
    if (!sanitizedData.procedure || !sanitizedData.description || !sanitizedData.risks) {
      throw new Error('Procedure, description, and risks are required for consent form');
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
        
        <div style="margin-top: 60px; display: flex; justify-content: space-between;">
            <div style="text-align: center; width: 45%;">
                <div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>
                <div>
                    <strong>Paciente ou Responsável</strong><br>
                    ${sanitizedData.patientName}
                </div>
            </div>
            
            <div style="text-align: center; width: 45%;">
                <div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>
                <div>
                    <strong>Profissional Responsável</strong><br>
                    ${sanitizedData.professionalName}<br>
                    ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
                </div>
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Termo de Consentimento', content);
    console.log('SUCCESS Consent form HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Consent form HTML generation failed:', error.message);
    throw new Error(`Failed to generate consent form HTML: ${error.message}`);
  }
};

/**
 * Exam Request Template
 */
export const generateExamRequestHTML = (data) => {
  console.log('DEBUG Starting exam request HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Exam request data validated successfully');
    
    if (!sanitizedData.content) {
      throw new Error('Exam content is required');
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
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Solicitação de Exames', content);
    console.log('SUCCESS Exam request HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Exam request HTML generation failed:', error.message);
    throw new Error(`Failed to generate exam request HTML: ${error.message}`);
  }
};

/**
 * Declaration Template
 */
export const generateDeclarationHTML = (data) => {
  console.log('DEBUG Starting declaration HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Declaration data validated successfully');
    
    if (!sanitizedData.content) {
      throw new Error('Declaration content is required');
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
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML(sanitizedData.title, content);
    console.log('SUCCESS Declaration HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Declaration HTML generation failed:', error.message);
    throw new Error(`Failed to generate declaration HTML: ${error.message}`);
  }
};

/**
 * LGPD Term Template
 */
export const generateLGPDHTML = (data) => {
  console.log('DEBUG Starting LGPD HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG LGPD data validated successfully');
    
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
        
        <div style="margin-top: 60px; display: flex; justify-content: space-between;">
            <div style="text-align: center; width: 45%;">
                <div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>
                <div>
                    <strong>Paciente ou Responsável</strong><br>
                    ${sanitizedData.patientName}
                </div>
            </div>
            
            <div style="text-align: center; width: 45%;">
                <div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>
                <div>
                    <strong>Profissional Responsável</strong><br>
                    ${sanitizedData.professionalName}<br>
                    ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
                </div>
            </div>
        </div>
    `;
    
    const html = getBaseHTML('Termo LGPD', content);
    console.log('SUCCESS LGPD HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR LGPD HTML generation failed:', error.message);
    throw new Error(`Failed to generate LGPD HTML: ${error.message}`);
  }
};

/**
 * Generic Document Template
 */
export const generateGenericHTML = (data) => {
  console.log('DEBUG Starting generic document HTML generation');
  
  try {
    const sanitizedData = validateAndSanitizeData(data);
    console.log('DEBUG Generic document data validated successfully');
    
    if (!sanitizedData.content) {
      throw new Error('Document content is required');
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
            <div class="signature-line"></div>
            <div>
                <strong>${sanitizedData.professionalName}</strong><br>
                ${sanitizedData.professionalSpecialty}<br>
                ${sanitizedData.crm ? `Registro Profissional: ${sanitizedData.crm}` : ''}
            </div>
        </div>
    `;
    
    const html = getBaseHTML(sanitizedData.title, content);
    console.log('SUCCESS Generic document HTML generated, length:', html.length);
    
    return html;
  } catch (error) {
    console.error('ERROR Generic document HTML generation failed:', error.message);
    throw new Error(`Failed to generate generic document HTML: ${error.message}`);
  }
};