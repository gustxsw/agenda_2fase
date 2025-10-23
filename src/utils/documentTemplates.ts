// Document templates for HTML generation - Clean professional templates
const templates = {
  certificate: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Atestado Médico</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 30px 0;
            text-align: center;
        }
        .content {
            margin: 30px 0;
            text-align: justify;
            font-size: 14px;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .signature {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #333;
            width: 300px;
            margin: 40px auto 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Atestado Médico</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="content">
        <p>Atesto para os devidos fins que o(a) paciente acima identificado(a) esteve sob meus cuidados médicos e apresenta quadro clínico que o(a) impossibilita de exercer suas atividades habituais.</p>
        
        <p><strong>Descrição:</strong> ${data.description}</p>
        
        ${data.cid ? `<p><strong>CID:</strong> ${data.cid}</p>` : ''}
        
        <p><strong>Período de afastamento:</strong> ${data.days} dia(s) a partir de ${new Date().toLocaleDateString('pt-BR')}.</p>
        
        <p>Este atestado é válido para todos os fins legais e administrativos.</p>
    </div>

    <div class="signature">
        ${data.signatureUrl ? 
          `<img src="${data.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
          '<div class="signature-line"></div>'
        }
        <div>
            <strong>${data.professionalName}</strong><br>
            ${data.professionalSpecialty || 'Profissional de Saúde'}<br>
            ${data.crm ? `Registro: ${data.crm}` : ''}
        </div>
    </div>

</body>
</html>`,

  prescription: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Receituário Médico</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .prescription-content {
            background: #fff;
            border: 2px solid #333;
            padding: 20px;
            margin: 20px 0;
            min-height: 200px;
        }
        .prescription-text {
            font-size: 16px;
            line-height: 2;
            white-space: pre-line;
        }
        .signature {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #333;
            width: 300px;
            margin: 40px auto 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Receituário Médico</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="prescription-content">
        <div class="prescription-text">${data.prescription}</div>
    </div>

    <div class="signature">
        ${data.signatureUrl ? 
          `<img src="${data.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
          '<div class="signature-line"></div>'
        }
        <div>
            <strong>${data.professionalName}</strong><br>
            ${data.professionalSpecialty || 'Profissional de Saúde'}<br>
            ${data.crm ? `Registro: ${data.crm}` : ''}
        </div>
    </div>

</body>
</html>`,

  consent_form: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Termo de Consentimento</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 18px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .content {
            margin: 20px 0;
            text-align: justify;
            font-size: 12px;
        }
        .section {
            margin: 15px 0;
        }
        .signature-area {
            margin-top: 60px;
            display: flex;
            justify-content: space-between;
        }
        .signature-box {
            text-align: center;
            width: 45%;
        }
        .signature-line {
            border-top: 1px solid #333;
            margin: 40px 0 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Termo de Consentimento Livre e Esclarecido</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="content">
        <div class="section">
            <h3>Procedimento a ser realizado:</h3>
            <p><strong>${data.procedure}</strong></p>
            <p>${data.description}</p>
        </div>

        <div class="section">
            <h3>Riscos e Benefícios:</h3>
            <p>${data.risks}</p>
        </div>

        <div class="section">
            <h3>Declaração de Consentimento:</h3>
            <p>Declaro que fui devidamente informado(a) sobre o procedimento acima descrito, seus riscos, benefícios e alternativas. Todas as minhas dúvidas foram esclarecidas e consinto com a realização do procedimento.</p>
            
            <p>Estou ciente de que nenhum procedimento médico é 100% isento de riscos e que complicações podem ocorrer, mesmo com todos os cuidados técnicos adequados.</p>
            
            <p>Autorizo o profissional de saúde a realizar o procedimento proposto e declaro que este consentimento é dado de forma livre e esclarecida.</p>
        </div>
    </div>

    <div class="signature-area">
        <div class="signature-box">
            <div class="signature-line"></div>
            <div>
                <strong>Paciente ou Responsável</strong><br>
                ${data.patientName}
            </div>
        </div>
        
        <div class="signature-box">
            ${data.signatureUrl ? 
              `<img src="${data.signatureUrl}" alt="Assinatura" style="max-width: 150px; max-height: 50px; margin: 20px auto 10px; display: block;" />` : 
              '<div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>'
            }
            <div>
                <strong>Profissional Responsável</strong><br>
                ${data.professionalName}<br>
                ${data.crm ? `Registro: ${data.crm}` : ''}
            </div>
        </div>
    </div>

</body>
</html>`,

  exam_request: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solicitação de Exames</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .exam-list {
            background: #fff;
            border: 2px solid #333;
            padding: 20px;
            margin: 20px 0;
            min-height: 150px;
        }
        .signature {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #333;
            width: 300px;
            margin: 40px auto 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Solicitação de Exames</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="exam-list">
        <h3>Exames Solicitados:</h3>
        <div style="white-space: pre-line; font-size: 16px; line-height: 2;">
${data.content}
        </div>
    </div>

    <div class="signature">
        ${data.signatureUrl ? 
          `<img src="${data.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
          '<div class="signature-line"></div>'
        }
        <div>
            <strong>${data.professionalName}</strong><br>
            ${data.professionalSpecialty || 'Profissional de Saúde'}<br>
            ${data.crm ? `Registro: ${data.crm}` : ''}
        </div>
    </div>

</body>
</html>`,

  declaration: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Declaração Médica</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .content {
            margin: 30px 0;
            text-align: justify;
            font-size: 14px;
            min-height: 200px;
        }
        .signature {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #333;
            width: 300px;
            margin: 40px auto 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Declaração Médica</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="content">
        <p>${data.content}</p>
    </div>

    <div class="signature">
        ${data.signatureUrl ? 
          `<img src="${data.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
          '<div class="signature-line"></div>'
        }
        <div>
            <strong>${data.professionalName}</strong><br>
            ${data.professionalSpecialty || 'Profissional de Saúde'}<br>
            ${data.crm ? `Registro: ${data.crm}` : ''}
        </div>
    </div>

</body>
</html>`,

  lgpd: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Termo LGPD</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 18px;
            font-weight: bold;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .content {
            margin: 20px 0;
            text-align: justify;
            font-size: 12px;
        }
        .section {
            margin: 15px 0;
        }
        .signature-area {
            margin-top: 60px;
            display: flex;
            justify-content: space-between;
        }
        .signature-box {
            text-align: center;
            width: 45%;
        }
        .signature-line {
            border-top: 1px solid #333;
            margin: 40px 0 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">Termo de Consentimento para Tratamento de Dados Pessoais (LGPD)</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="content">
        <div class="section">
            <h4>1. FINALIDADE DO TRATAMENTO DE DADOS</h4>
            <p>Os dados pessoais coletados serão utilizados exclusivamente para:</p>
            <ul>
                <li>Prestação de serviços de saúde e acompanhamento médico;</li>
                <li>Manutenção do histórico médico e prontuário;</li>
                <li>Comunicação sobre consultas e tratamentos;</li>
                <li>Cumprimento de obrigações legais e regulamentares.</li>
            </ul>
        </div>

        <div class="section">
            <h4>2. DADOS COLETADOS</h4>
            <p>Serão tratados dados pessoais como nome, CPF, endereço, telefone, email, informações de saúde e histórico médico.</p>
        </div>

        <div class="section">
            <h4>3. COMPARTILHAMENTO</h4>
            <p>Os dados não serão compartilhados com terceiros, exceto quando necessário para a prestação do serviço médico ou por determinação legal.</p>
        </div>

        <div class="section">
            <h4>4. DIREITOS DO TITULAR</h4>
            <p>Você tem direito a acessar, corrigir, excluir ou solicitar a portabilidade de seus dados, conforme a Lei Geral de Proteção de Dados (LGPD).</p>
        </div>

        <div class="section">
            <h4>5. CONSENTIMENTO</h4>
            <p>Ao assinar este termo, declaro que:</p>
            <ul>
                <li>Fui informado(a) sobre o tratamento dos meus dados pessoais;</li>
                <li>Compreendo as finalidades do tratamento;</li>
                <li>Consinto com o tratamento dos meus dados conforme descrito;</li>
                <li>Posso revogar este consentimento a qualquer momento.</li>
            </ul>
        </div>
    </div>

    <div class="signature-area">
        <div class="signature-box">
            <div class="signature-line"></div>
            <div>
                <strong>Paciente ou Responsável</strong><br>
                ${data.patientName}
            </div>
        </div>
        
        <div class="signature-box">
            ${data.signatureUrl ? 
              `<img src="${data.signatureUrl}" alt="Assinatura" style="max-width: 150px; max-height: 50px; margin: 20px auto 10px; display: block;" />` : 
              '<div style="border-top: 1px solid #000; margin: 40px 0 10px;"></div>'
            }
            <div>
                <strong>Profissional Responsável</strong><br>
                ${data.professionalName}<br>
                ${data.crm ? `Registro: ${data.crm}` : ''}
            </div>
        </div>
    </div>

</body>
</html>`,

  other: (data: any) => `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${data.title}</title>
    <style>
        body {
            font-family: 'Times New Roman', serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            background: white;
            color: #333;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
            margin: 30px 0;
            text-align: center;
        }
        .patient-info {
            background: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #333;
            margin: 20px 0;
        }
        .content {
            margin: 30px 0;
            text-align: justify;
            font-size: 14px;
            min-height: 200px;
            white-space: pre-line;
        }
        .signature {
            margin-top: 60px;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #333;
            width: 300px;
            margin: 40px auto 10px;
        }
        .signature-image {
            max-width: 300px;
            max-height: 100px;
            margin: 20px auto 10px;
            display: block;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            background: white;
        }
        @media print {
            body { margin: 0; padding: 20px; }
        }
    </style>
</head>
<body>

    <div class="title">${data.title}</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${data.patientName}<br>
        <strong>CPF:</strong> ${data.patientCpf}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString('pt-BR')}
    </div>

    <div class="content">
        ${data.content}
    </div>

    <div class="signature">
        ${data.signatureUrl ? 
          `<img src="${data.signatureUrl}" alt="Assinatura" class="signature-image" />` : 
          '<div class="signature-line"></div>'
        }
        <div>
            <strong>${data.professionalName}</strong><br>
            ${data.professionalSpecialty || 'Profissional de Saúde'}<br>
            ${data.crm ? `Registro: ${data.crm}` : ''}
        </div>
    </div>

</body>
</html>`
};

// Generate HTML document
export const generateDocumentHTML = (documentType: string, templateData: any, professionalId?: number): string => {
  try {
    console.log('🔄 Generating HTML for document type:', documentType, 'with professional ID:', professionalId);
    
    // Get the template function
    const templateFunction = templates[documentType as keyof typeof templates] || templates.other;
    
    // Generate HTML content
    const htmlContent = templateFunction(templateData);
    
    console.log('✅ HTML content generated, length:', htmlContent.length);
    
    return htmlContent;
  } catch (error) {
    console.error('❌ Error generating HTML document:', error);
    throw new Error(`Erro ao gerar documento: ${error.message}`);
  }
};