import React, { useState, useEffect } from "react";
import {
  FileText,
  X,
  Eye,
  Download,
  ExternalLink,
  AlertCircle,
} from "lucide-react";

type DocumentViewModalProps = {
  isOpen: boolean;
  onClose: () => void;
  documentUrl: string;
  documentTitle: string;
  documentType?: string;
};

const DocumentViewModal: React.FC<DocumentViewModalProps> = ({
  isOpen,
  onClose,
  documentUrl,
  documentTitle,
  documentType,
}) => {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [documentContent, setDocumentContent] = useState("");

  useEffect(() => {
    if (isOpen && documentUrl) {
      loadDocument();
    }
  }, [isOpen, documentUrl]);

  const loadDocument = async () => {
    try {
      setIsLoading(true);
      setError("");

      console.log("🔄 Loading document from URL:", documentUrl);

      // Check if it's a PDF or HTML document
      const isPDF =
        documentUrl.toLowerCase().includes(".pdf") || documentType === "pdf";

      if (isPDF) {
        // For PDF documents, we'll show an embedded viewer
        setDocumentContent("PDF_VIEWER");
      } else {
        // For HTML documents, fetch the content
        const response = await fetch(documentUrl);

        if (!response.ok) {
          throw new Error("Não foi possível carregar o documento");
        }

        const content = await response.text();
        setDocumentContent(content);
      }
    } catch (error) {
      console.error("❌ Error loading document:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao carregar documento"
      );
    } finally {
      setIsLoading(false);
    }
  };

  const openInNewTab = () => {
    window.open(documentUrl, "_blank", "noopener,noreferrer");
  };

  const downloadDocument = () => {
    const link = document.createElement("a");
    link.href = documentUrl;
    link.download = documentTitle;
    link.target = "_blank";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (!isOpen) return null;

  const isPDF = documentContent === "PDF_VIEWER";

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-6xl max-h-[95vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gray-50">
          <div className="flex items-center">
            <FileText className="h-6 w-6 text-red-600 mr-3" />
            <div>
              <h2 className="text-xl font-bold text-gray-900">
                {documentTitle}
              </h2>
              <p className="text-sm text-gray-600">Visualização do documento</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg flex items-center">
            <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Document Content */}
        <div className="flex-1 overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
                <p className="text-gray-600">Carregando documento...</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <AlertCircle className="h-16 w-16 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Erro ao carregar documento
                </h3>
                <p className="text-gray-600 mb-4">{error}</p>
                <button
                  onClick={openInNewTab}
                  className="btn btn-primary flex items-center"
                >
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Abrir em Nova Aba
                </button>
              </div>
            </div>
          ) : isPDF ? (
            <div className="h-full flex flex-col">
              <div className="flex-1 p-6">
                <div className="bg-gray-100 rounded-lg h-full flex items-center justify-center">
                  <div className="text-center">
                    <FileText className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      Documento PDF
                    </h3>
                    <p className="text-gray-600 mb-6">
                      Para visualizar este documento PDF, clique em um dos
                      botões abaixo:
                    </p>
                    <div className="flex justify-center space-x-3">
                      <button
                        onClick={openInNewTab}
                        className="btn btn-primary flex items-center"
                      >
                        <ExternalLink className="h-4 w-4 mr-2" />
                        Abrir em Nova Aba
                      </button>
                      <button
                        onClick={downloadDocument}
                        className="btn btn-secondary flex items-center"
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Download
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-6">
              <div className="bg-white border border-gray-200 rounded-lg shadow-sm">
                <div
                  className="p-8"
                  dangerouslySetInnerHTML={{ __html: documentContent }}
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
          )}
        </div>

        {/* Action Buttons */}
        {!isLoading && !error && (
          <div className="p-6 border-t border-gray-200 bg-gray-50 flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <Eye className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">
                Visualização do documento
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DocumentViewModal;
