import React, { useState, useRef } from "react";
import {
  Upload,
  X,
  Check,
  Eye,
  AlertCircle,
  FileImage,
  Trash2,
} from "lucide-react";

type UploadSignatureModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  currentSignatureUrl?: string | null;
};

const UploadSignatureModal: React.FC<UploadSignatureModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  currentSignatureUrl,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setError("");
    setSuccess("");

    // Validate file type
    if (!file.type.startsWith("image/")) {
      setError(
        "Por favor, selecione apenas arquivos de imagem (PNG, JPEG, JPG)"
      );
      return;
    }

    // Validate file size (2MB max for signatures)
    if (file.size > 2 * 1024 * 1024) {
      setError("A imagem deve ter no máximo 2MB");
      return;
    }

    setSelectedFile(file);

    // Create preview URL
    const reader = new FileReader();
    reader.onload = (e) => {
      setPreviewUrl(e.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  const clearSelection = () => {
    setSelectedFile(null);
    setPreviewUrl(null);
    setError("");
    setSuccess("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Selecione uma imagem para fazer upload");
      return;
    }

    try {
      setIsUploading(true);
      setError("");
      setSuccess("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Get current user ID from localStorage
      const userData = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = userData.id;

      if (!userId) {
        throw new Error("Usuário não identificado");
      }

      console.log("🔄 Uploading signature for professional:", userId);

      const formData = new FormData();
      formData.append("signature", selectedFile);

      const response = await fetch(
        `${apiUrl}/api/professionals/${userId}/signature`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        }
      );

      console.log("📡 Signature upload response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Signature upload error:", errorData);
        throw new Error(
          errorData.message || "Erro ao fazer upload da assinatura"
        );
      }

      const result = await response.json();
      console.log("✅ Signature uploaded successfully:", result);

      setSuccess("Assinatura digital salva com sucesso!");

      // Clear form and close modal after success
      setTimeout(() => {
        clearSelection();
        onSuccess();
        onClose();
      }, 1500);
    } catch (error) {
      console.error("❌ Error uploading signature:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Erro ao fazer upload da assinatura"
      );
    } finally {
      setIsUploading(false);
    }
  };

  const removeCurrentSignature = async () => {
    if (!currentSignatureUrl) return;

    try {
      setIsUploading(true);
      setError("");
      setSuccess("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const userData = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = userData.id;

      console.log("🔄 Removing current signature for professional:", userId);

      const response = await fetch(
        `${apiUrl}/api/professionals/${userId}/signature`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      console.log("📡 Signature removal response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao remover assinatura");
      }

      setSuccess("Assinatura removida com sucesso!");

      setTimeout(() => {
        onSuccess();
        onClose();
      }, 1500);
    } catch (error) {
      console.error("❌ Error removing signature:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao remover assinatura"
      );
    } finally {
      setIsUploading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold flex items-center">
              <FileImage className="h-6 w-6 text-red-600 mr-2" />
              {currentSignatureUrl
                ? "Gerenciar Assinatura Digital"
                : "Upload de Assinatura Digital"}
            </h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
              disabled={isUploading}
            >
              <X className="h-6 w-6" />
            </button>
          </div>
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
            <Check className="h-5 w-5 mr-2 flex-shrink-0" />
            {success}
          </div>
        )}

        <div className="p-6">
          {/* Current Signature Display */}
          {currentSignatureUrl && !selectedFile && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                Assinatura Atual
              </h3>
              <div className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-lg p-6">
                <div className="text-center">
                  <img
                    src={currentSignatureUrl}
                    alt="Assinatura atual"
                    className="max-w-full max-h-32 mx-auto mb-4 border border-gray-200 rounded"
                    style={{ maxHeight: "120px" }}
                  />
                  <p className="text-sm text-gray-600 mb-4">
                    Esta é sua assinatura digital atual
                  </p>
                  <div className="flex justify-center space-x-3">
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      className="btn btn-primary flex items-center"
                      disabled={isUploading}
                    >
                      <Upload className="h-4 w-4 mr-2" />
                      Alterar Assinatura
                    </button>
                    <button
                      onClick={removeCurrentSignature}
                      className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
                      disabled={isUploading}
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Remover Assinatura
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* File Upload Area */}
          {(!currentSignatureUrl || selectedFile) && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">
                {selectedFile
                  ? "Nova Assinatura Selecionada"
                  : "Selecionar Assinatura"}
              </h3>

              {!selectedFile ? (
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-pointer hover:border-red-400 hover:bg-red-50 transition-colors"
                >
                  <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-lg font-medium text-gray-700 mb-2">
                    Clique para selecionar sua assinatura
                  </p>
                  <p className="text-sm text-gray-500">
                    Formatos aceitos: PNG, JPEG, JPG (máximo 2MB)
                  </p>
                </div>
              ) : (
                <div className="bg-gray-50 border-2 border-gray-300 rounded-lg p-6">
                  <div className="text-center">
                    <img
                      src={previewUrl || ""}
                      alt="Preview da assinatura"
                      className="max-w-full max-h-32 mx-auto mb-4 border border-gray-200 rounded bg-white"
                      style={{ maxHeight: "120px" }}
                    />
                    <p className="text-sm text-gray-600 mb-4">
                      <strong>Arquivo:</strong> {selectedFile.name}
                    </p>
                    <p className="text-xs text-gray-500 mb-4">
                      <strong>Tamanho:</strong>{" "}
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </p>
                    <div className="flex justify-center space-x-3">
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="btn btn-secondary flex items-center"
                        disabled={isUploading}
                      >
                        <Upload className="h-4 w-4 mr-2" />
                        Escolher Outra
                      </button>
                      <button
                        onClick={clearSelection}
                        className="btn btn-outline flex items-center"
                        disabled={isUploading}
                      >
                        <X className="h-4 w-4 mr-2" />
                        Cancelar
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/jpg"
                onChange={handleFileSelect}
                className="hidden"
                disabled={isUploading}
              />
            </div>
          )}

          {/* Instructions */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h4 className="font-medium text-blue-900 mb-2">
              💡 Dicas para uma boa assinatura:
            </h4>
            <ul className="text-sm text-blue-700 space-y-1">
              <li>• Use fundo branco ou transparente</li>
              <li>• Assinatura deve estar bem visível e legível</li>
              <li>• Evite bordas ou elementos desnecessários</li>
              <li>• Tamanho recomendado: 300x100 pixels</li>
              <li>
                • A assinatura será redimensionada automaticamente nos
                documentos
              </li>
            </ul>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end space-x-3">
            <button
              onClick={onClose}
              className="btn btn-secondary"
              disabled={isUploading}
            >
              Cancelar
            </button>

            {selectedFile && (
              <button
                onClick={handleUpload}
                className={`btn btn-primary flex items-center ${
                  isUploading ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isUploading}
              >
                {isUploading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Salvando...
                  </>
                ) : (
                  <>
                    <Check className="h-5 w-5 mr-2" />
                    Salvar Assinatura
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Loading Overlay */}
        {isUploading && (
          <div className="absolute inset-0 bg-white bg-opacity-90 flex items-center justify-center rounded-xl">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-700 font-medium">
                Processando assinatura...
              </p>
              <p className="text-sm text-gray-500 mt-2">
                Fazendo upload e salvando no sistema
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UploadSignatureModal;
