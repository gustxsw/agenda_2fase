import React, { useState } from "react";
import {
  X,
  AlertTriangle,
  Check,
  MessageSquare,
  Calendar,
  User,
  Users,
  MapPin,
} from "lucide-react";

type CancelConsultationModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (reason?: string) => Promise<void>;
  consultationData: {
    id: number;
    patient_name: string;
    service_name: string;
    date: string;
    professional_name?: string;
    location_name?: string;
    is_dependent?: boolean;
    patient_type?: "convenio" | "private";
  } | null;
  isLoading?: boolean;
};

const CancelConsultationModal: React.FC<CancelConsultationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  consultationData,
  isLoading = false,
}) => {
  const [cancellationReason, setCancellationReason] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleConfirm = async () => {
    try {
      setIsSubmitting(true);

      // Call the cancel API endpoint
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(
        `${apiUrl}/api/consultations/${consultationData.id}/cancel`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            cancellation_reason: cancellationReason.trim() || null,
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao cancelar consulta");
      }

      await onConfirm(cancellationReason.trim() || undefined);
      setCancellationReason("");
    } catch (error) {
      console.error("Error in handleConfirm:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

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

  const handleClose = () => {
    if (isSubmitting) return; // Prevent closing while submitting
    setCancellationReason("");
    onClose();
  };

  const formatDate = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const cancelModalUtcDate = new Date(dateString);
    const cancelModalLocalDate = new Date(
      cancelModalUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return cancelModalLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getPatientTypeDisplay = () => {
    if (!consultationData)
      return { icon: <User className="h-4 w-4" />, label: "Paciente" };

    if (consultationData.patient_type === "private") {
      return {
        icon: <User className="h-4 w-4 text-purple-600" />,
        label: "Particular",
      };
    } else if (consultationData.is_dependent) {
      return {
        icon: <Users className="h-4 w-4 text-blue-600" />,
        label: "Dependente",
      };
    } else {
      return {
        icon: <User className="h-4 w-4 text-green-600" />,
        label: "Titular",
      };
    }
  };

  if (!isOpen || !consultationData) return null;

  const patientTypeInfo = getPatientTypeDisplay();
  const isProcessing = isLoading || isSubmitting;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-lg">
        <div className="p-6 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold flex items-center">
              <AlertTriangle className="h-6 w-6 text-red-600 mr-2" />
              Cancelar Consulta
            </h2>
            <button
              onClick={handleClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
              disabled={isProcessing}
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        <div className="p-6">
          {/* Consultation Details */}
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            <h3 className="font-medium text-gray-900 mb-3 flex items-center">
              <Calendar className="h-5 w-5 text-red-600 mr-2" />
              Detalhes da Consulta
            </h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center">
                {patientTypeInfo.icon}
                <span className="ml-2">
                  <strong>Paciente:</strong> {consultationData.patient_name}
                  <span className="ml-2 px-2 py-1 bg-gray-100 text-gray-700 rounded-full text-xs">
                    {patientTypeInfo.label}
                  </span>
                </span>
              </div>
              <p>
                <strong>Serviço:</strong> {consultationData.service_name}
              </p>
              <p>
                <strong>Data/Hora:</strong> {formatDate(consultationData.date)}
              </p>
              {consultationData.professional_name && (
                <p>
                  <strong>Profissional:</strong>{" "}
                  {consultationData.professional_name}
                </p>
              )}
              {consultationData.location_name && (
                <div className="flex items-center">
                  <MapPin className="h-4 w-4 text-gray-400 mr-1" />
                  <span>
                    <strong>Local:</strong> {consultationData.location_name}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Warning */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 text-yellow-600 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-medium text-yellow-800 mb-1">Atenção</h4>
                <p className="text-sm text-yellow-700">
                  Esta ação irá cancelar a consulta permanentemente. O horário
                  será liberado imediatamente para novos agendamentos, mas a
                  consulta será mantida no histórico como cancelada.
                </p>
              </div>
            </div>
          </div>

          {/* Cancellation Reason */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              <MessageSquare className="h-4 w-4 inline mr-1" />
              Motivo do Cancelamento (opcional)
            </label>
            <textarea
              value={cancellationReason}
              onChange={(e) => setCancellationReason(e.target.value)}
              className="w-full p-3 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent resize-none transition-all"
              rows={3}
              placeholder="Descreva o motivo do cancelamento (ex: paciente faltou, reagendamento solicitado, etc.)"
              disabled={isProcessing}
              maxLength={500}
            />
            <p className="text-xs text-gray-500 mt-1">
              {cancellationReason.length}/500 caracteres
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end space-x-3">
            <button
              onClick={handleClose}
              className="btn btn-secondary"
              disabled={isProcessing}
            >
              Voltar
            </button>
            <button
              onClick={handleConfirm}
              className={`btn bg-red-600 text-white hover:bg-red-700 flex items-center ${
                isProcessing ? "opacity-70 cursor-not-allowed" : ""
              }`}
              disabled={isProcessing}
            >
              {isProcessing ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Cancelando...
                </>
              ) : (
                <>
                  <Check className="h-4 w-4 mr-2" />
                  Confirmar Cancelamento
                </>
              )}
            </button>
          </div>
        </div>

        {/* Processing Overlay */}
        {isProcessing && (
          <div className="absolute inset-0 bg-white bg-opacity-90 flex items-center justify-center rounded-xl">
            <div className="text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-600 mx-auto mb-3"></div>
              <p className="text-gray-700 font-medium">
                Cancelando consulta...
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Liberando horário na agenda
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CancelConsultationModal;
