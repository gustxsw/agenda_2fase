import React from 'react';
import { Download, FileText, AlertCircle } from 'lucide-react';

type SimplePDFGeneratorProps = {
  htmlContent: string;
  fileName: string;
  title: string;
  onSuccess?: () => void;
  onError?: (error: string) => void;
};

const SimplePDFGenerator: React.FC<SimplePDFGeneratorProps> = ({
  htmlContent,
  fileName,
  title,
  onSuccess,
  onError
}) => {
  const generatePrintablePDF = () => {
    try {
      // Create a new window for printing
      const printWindow = window.open('', '_blank');
      
      if (!printWindow) {
        throw new Error('Popup bloqueado. Permita popups para gerar PDF.');
      }

      // Enhanced CSS specifically for print
      const printCSS = `
        <style>
          @page { 
            size: A4; 
            margin: 15mm; 
          }
          
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          
          body {
            font-family: 'Times New Roman', serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000000 !important;
            background: #ffffff !important;
            padding: 20px !important;
            margin: 0 !important;
          }
          
          .document-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #c11c22 !important;
            page-break-after: avoid;
          }
          
          .logo {
            font-size: 24px !important;
            font-weight: bold !important;
            color: #c11c22 !important;
            margin-bottom: 10px;
          }
          
          .subtitle {
            font-size: 14px !important;
            color: #666666 !important;
          }
          
          .document-title {
            font-size: 20px !important;
            font-weight: bold !important;
            text-transform: uppercase;
            text-align: center;
            margin: 30px 0 !important;
            color: #000000 !important;
            page-break-after: avoid;
          }
          
          .patient-info {
            background: #f9f9f9 !important;
            padding: 15px !important;
            margin: 20px 0 !important;
            border-left: 4px solid #c11c22 !important;
            border-radius: 4px;
            page-break-inside: avoid;
          }
          
          .content-section {
            margin: 20px 0 !important;
            padding: 15px !important;
            background: #ffffff !important;
            page-break-inside: avoid;
          }
          
          .section-title {
            font-size: 16px !important;
            font-weight: bold !important;
            color: #c11c22 !important;
            margin-bottom: 10px !important;
            border-bottom: 1px solid #eeeeee !important;
            padding-bottom: 5px !important;
          }
          
          .prescription-box {
            border: 2px solid #c11c22 !important;
            padding: 20px !important;
            margin: 20px 0 !important;
            background: #ffffff !important;
            min-height: 150px;
            page-break-inside: avoid;
          }
          
          .prescription-content {
            font-size: 16px !important;
            line-height: 2 !important;
            white-space: pre-line;
            color: #000000 !important;
          }
          
          .signature-area {
            margin-top: 60px !important;
            text-align: center;
            page-break-before: avoid;
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
            color: #666666 !important;
            border-top: 1px solid #dddddd !important;
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
            color: #666666 !important;
            margin-bottom: 5px !important;
          }
          
          .vital-sign-value {
            font-weight: bold !important;
            color: #c11c22 !important;
          }
          
          p {
            margin: 10px 0 !important;
            text-align: justify;
            color: #000000 !important;
          }
          
          strong {
            font-weight: bold !important;
            color: #000000 !important;
          }
          
          ul {
            margin: 10px 0 !important;
            padding-left: 20px !important;
          }
          
          li {
            margin: 5px 0 !important;
            color: #000000 !important;
          }
          
          h3, h4 {
            color: #c11c22 !important;
            margin: 15px 0 10px 0 !important;
          }
          
          /* Force all text to be black */
          * {
            color: #000000 !important;
          }
          
          @media print {
            body { 
              margin: 0 !important; 
              padding: 20px !important; 
              background: #ffffff !important;
            }
            .document-header { page-break-after: avoid; }
            .signature-area { page-break-before: avoid; }
            * { 
              color: #000000 !important; 
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }
          }
        </style>
      `;

      // Write content to new window
      printWindow.document.write(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${title}</title>
          ${printCSS}
        </head>
        <body>
          ${htmlContent}
          <script>
            window.onload = function() {
              // Auto-print when page loads
              setTimeout(function() {
                window.print();
                // Close window after printing
                setTimeout(function() {
                  window.close();
                }, 1000);
              }, 500);
            };
          </script>
        </body>
        </html>
      `);

      printWindow.document.close();
      
      if (onSuccess) {
        onSuccess();
      }
    } catch (error) {
      console.error('Error generating printable PDF:', error);
      if (onError) {
        onError(error instanceof Error ? error.message : 'Erro ao gerar PDF');
      }
    }
  };

  const downloadAsHTML = () => {
    try {
      const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${fileName.replace(/[^a-zA-Z0-9\s]/g, '').replace(/\s+/g, '_')}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      if (onSuccess) {
        onSuccess();
      }
    } catch (error) {
      console.error('Error downloading HTML:', error);
      if (onError) {
        onError(error instanceof Error ? error.message : 'Erro ao baixar HTML');
      }
    }
  };

  return (
    <div className="flex space-x-3">
      <button
        onClick={generatePrintablePDF}
        className="btn btn-primary flex items-center"
        title="Gerar PDF para impressão"
      >
        <FileText className="h-4 w-4 mr-2" />
        Imprimir PDF
      </button>
      
      <button
        onClick={downloadAsHTML}
        className="btn btn-secondary flex items-center"
        title="Baixar como HTML"
      >
        <Download className="h-4 w-4 mr-2" />
        Baixar HTML
      </button>
    </div>
  );
};

export default SimplePDFGenerator;