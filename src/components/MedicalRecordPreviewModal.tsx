import React, { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import {
  FileText,
  Download,
  Save,
  X,
  Eye,
  AlertCircle,
  CheckCircle,
  Printer,
} from "lucide-react";

declare global {
  interface Window {
    html2pdf: any;
  }
}

type MedicalRecordPreviewModalProps = {
  isOpen: boolean;
  onClose: () => void;
  recordData: {
    id: number;
    patient_name: string;
    chief_complaint?: string;
    history_present_illness?: string;
    past_medical_history?: string;
    medications?: string;
    allergies?: string;
    physical_examination?: string;
    diagnosis?: string;
    treatment_plan?: string;
    notes?: string;
    vital_signs?: any;
    created_at: string;
  };
  professionalData: {
    name: string;
    specialty: string;
    crm: string;
  };
};

const MedicalRecordPreviewModal: React.FC<MedicalRecordPreviewModalProps> = ({
  isOpen,
  onClose,
  recordData,
  professionalData,
}) => {
  const { user } = useAuth();
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [signatureUrl, setSignatureUrl] = useState<string | null>(null);

  // Get API URL
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }
    return "http://localhost:3001";
  };

  // Fetch professional signature
  useEffect(() => {
    const fetchSignature = async () => {
      try {
        const token = localStorage.getItem("token");
        const apiUrl = getApiUrl();

        const response = await fetch(
          `${apiUrl}/api/professionals/${user?.id}/signature`,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );

        if (response.ok) {
          const signatureData = await response.json();
          setSignatureUrl(signatureData.signature_url);
        }
      } catch (error) {
        console.warn("Could not load signature:", error);
      }
    };

    if (isOpen && user?.id) {
      fetchSignature();
    }
  }, [isOpen, user?.id]);

  // Generate HTML content for the medical record
  const generateHTML = () => {
    const vitalSigns = recordData.vital_signs || {};
    const hasVitalSigns = Object.values(vitalSigns).some(
      (value) => value && value.toString().trim()
    );

    let vitalSignsHTML = "";
    if (hasVitalSigns) {
      const vitalSignItems = [
        { label: "Pressão Arterial", value: vitalSigns.blood_pressure },
        { label: "Freq. Cardíaca", value: vitalSigns.heart_rate },
        { label: "Temperatura", value: vitalSigns.temperature },
        { label: "Freq. Respiratória", value: vitalSigns.respiratory_rate },
        { label: "Sat. O₂", value: vitalSigns.oxygen_saturation },
        { label: "Peso", value: vitalSigns.weight },
        { label: "Altura", value: vitalSigns.height },
      ].filter((item) => item.value && item.value.toString().trim());

      if (vitalSignItems.length > 0) {
        vitalSignsHTML = `
          <div class="section">
            <h3>Sinais Vitais</h3>
            <div class="vital-signs-grid">
              ${vitalSignItems
                .map(
                  (item) => `
                <div class="vital-sign-item">
                  <div class="vital-sign-label">${item.label}</div>
                  <div class="vital-sign-value">${item.value}</div>
                </div>
              `
                )
                .join("")}
            </div>
          </div>
        `;
      }
    }

    const medicalSections = [
      { title: "Queixa Principal", content: recordData.chief_complaint },
      {
        title: "História da Doença Atual",
        content: recordData.history_present_illness,
      },
      {
        title: "História Médica Pregressa",
        content: recordData.past_medical_history,
      },
      { title: "Medicamentos em Uso", content: recordData.medications },
      { title: "Alergias", content: recordData.allergies },
      { title: "Exame Físico", content: recordData.physical_examination },
      { title: "Diagnóstico", content: recordData.diagnosis },
      { title: "Plano de Tratamento", content: recordData.treatment_plan },
      { title: "Observações Gerais", content: recordData.notes },
    ].filter((section) => section.content && section.content.trim());

    const medicalSectionsHTML = medicalSections
      .map(
        (section) => `
      <div class="section">
        <h3>${section.title}</h3>
        <p>${section.content}</p>
      </div>
    `
      )
      .join("");

    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prontuário Médico - ${recordData.patient_name}</title>
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
            color: #000000 !important;
            background: #ffffff !important;
            padding: 20px !important;
            margin: 0 !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #333;
            padding-bottom: 20px;
        }
        
        .logo {
            font-size: 24px !important;
            font-weight: bold !important;
            color: #333 !important;
            margin-bottom: 10px;
        }
        
        .title {
            font-size: 20px !important;
            font-weight: bold !important;
            text-transform: uppercase;
            margin: 30px 0 !important;
            text-align: center;
            color: #000000 !important;
        }
        
        .patient-info {
            background: #f9f9f9 !important;
            padding: 15px !important;
            border-left: 4px solid #333 !important;
            margin: 20px 0 !important;
            border-radius: 4px;
        }
        
        .section {
            margin: 20px 0 !important;
            padding: 15px !important;
            border: 1px solid #ddd !important;
            border-radius: 5px;
            page-break-inside: avoid;
            background: #ffffff !important;
        }
        
        .section h3 {
            margin: 0 0 10px 0 !important;
            color: #333 !important;
            font-size: 16px !important;
            border-bottom: 1px solid #eee !important;
            padding-bottom: 5px !important;
            font-weight: bold !important;
        }
        
        .section p {
            color: #000000 !important;
            margin: 10px 0 !important;
            text-align: justify;
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
            color: #666666 !important;
            margin-bottom: 5px !important;
        }
        
        .vital-sign-value {
            font-weight: bold !important;
            color: #333 !important;
        }
        
        .signature {
            margin-top: 60px !important;
            text-align: center;
        }
        
        .signature-line {
            border-top: 1px solid #000000 !important;
            width: 300px;
            margin: 40px auto 10px !important;
        }
        
        .signature-image {
            max-width: 200px !important;
            max-height: 60px !important;
            margin: 20px auto 10px !important;
            display: block !important;
        }
        
        .footer {
            margin-top: 40px !important;
            text-align: center;
            font-size: 12px !important;
            color: #666666 !important;
            border-top: 1px solid #dddddd !important;
            padding-top: 20px !important;
        }
        
        /* Force all text to be visible */
        * {
            color: #000000 !important;
        }
        
        h1, h2, h3, h4, h5, h6 {
            color: #333 !important;
        }
        
        strong {
            font-weight: bold !important;
            color: #000000 !important;
        }
        
        @media print {
            body { 
                margin: 0 !important; 
                padding: 20px !important; 
                background: #ffffff !important;
            }
            .section { 
                page-break-inside: avoid; 
                background: #ffffff !important;
            }
            * { 
                color: #000000 !important; 
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }
        }
    </style>
</head>
<body>

    <div class="title">Prontuário Médico</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${recordData.patient_name}<br>
        <strong>Data do Atendimento:</strong> ${new Date(
          recordData.created_at
        ).toLocaleDateString("pt-BR")}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString(
          "pt-BR"
        )}
    </div>

    ${vitalSignsHTML}

    ${medicalSectionsHTML}

    ${
      medicalSections.length === 0
        ? `
    <div class="section">
        <p><em>Prontuário médico sem informações clínicas detalhadas registradas.</em></p>
    </div>
    `
        : ""
    }

    <div class="signature">
        ${
          signatureUrl
            ? `<img src="${signatureUrl}" alt="Assinatura" class="signature-image" />`
            : '<div class="signature-line"></div>'
        }
        <div>
            <strong>${professionalData.name}</strong><br>
            ${professionalData.specialty}<br>
            ${professionalData.crm ? `Registro: ${professionalData.crm}` : ""}
        </div>
    </div>

</body>
</html>`;
  };

  // Função de impressão direta e confiável
  const printMedicalRecord = () => {
    try {
      setError("");
      setSuccess("");

      console.log("🔄 Starting medical record print process");

      // Gerar HTML otimizado
      const htmlContent = generateHTML();

      // Criar nova janela para impressão
      const printWindow = window.open("", "_blank", "width=800,height=600");

      if (!printWindow) {
        throw new Error("Popup foi bloqueado. Permita popups para imprimir.");
      }

      // Escrever conteúdo na nova janela
      printWindow.document.write(htmlContent);
      printWindow.document.close();

      // Aguardar carregamento e imprimir
      printWindow.onload = () => {
        setTimeout(() => {
          printWindow.print();

          // Fechar janela após impressão
          setTimeout(() => {
            printWindow.close();
          }, 1000);
        }, 500);
      };

      setSuccess("Janela de impressão aberta! Use Ctrl+P se necessário.");

      console.log("✅ Print window opened successfully");
    } catch (error) {
      console.error("❌ Error in print process:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao imprimir prontuário"
      );
    }
  };

  // Função para baixar como HTML
  const downloadAsHTML = () => {
    try {
      const htmlContent = generateHTML();
      const blob = new Blob([htmlContent], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Prontuario_${recordData.patient_name
        .replace(/[^a-zA-Z0-9\s]/g, "")
        .replace(/\s+/g, "_")}_${new Date().toISOString().split("T")[0]}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setSuccess("Prontuário baixado em HTML com sucesso!");
    } catch (error) {
      console.error("Error downloading HTML:", error);
      setError("Erro ao baixar HTML");
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-6xl max-h-[95vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gray-50">
          <div className="flex items-center">
            <FileText className="h-6 w-6 text-red-600 mr-3" />
            <div>
              <h2 className="text-xl font-bold text-gray-900">
                Preview do Prontuário Médico
              </h2>
              <p className="text-sm text-gray-600">
                Paciente: {recordData.patient_name}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Feedback Messages */}
        {error && (
          <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg flex items-center">
            <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            {error}
          </div>
        )}

        {success && (
          <div className="mx-6 mt-4 bg-green-50 text-green-600 p-3 rounded-lg flex items-center">
            <CheckCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            {success}
          </div>
        )}

        {/* Document Preview */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="bg-white border border-gray-200 rounded-lg shadow-sm">
            <div
              className="p-8"
              dangerouslySetInnerHTML={{ __html: generateHTML() }}
              style={{
                fontFamily: "Times New Roman, serif",
                lineHeight: "1.6",
                color: "#333",
                maxWidth: "210mm",
                margin: "0 auto",
                backgroundColor: "white",
              }}
            />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="p-6 border-t border-gray-200 bg-gray-50 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Eye className="h-4 w-4 text-gray-500" />
            <span className="text-sm text-gray-600">
              Visualização do prontuário médico
            </span>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={downloadAsHTML}
              className="btn btn-secondary flex items-center"
            >
              <Download className="h-4 w-4 mr-2" />
              Baixar HTML
            </button>

            <button
              onClick={printMedicalRecord}
              className="btn btn-primary flex items-center"
            >
              <Printer className="h-4 w-4 mr-2" />
              Imprimir PDF
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MedicalRecordPreviewModal;
