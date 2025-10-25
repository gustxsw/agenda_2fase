import type React from "react";
import { useState, useEffect } from "react";
import { Calendar, X, Check, AlertCircle, User, Users } from "lucide-react";
import TimeInput from "./TimeInput";
import {
  validateTimeSlot,
  type SlotDuration,
} from "../utils/timeSlotValidation";
import {
  utcToLocalDateInput,
  utcToLocalTimeInput,
  toUTCString,
} from "../utils/dateHelpers";

type Consultation = {
  id: number;
  date: string;
  client_name: string;
  service_name: string;
  status: "scheduled" | "confirmed" | "completed" | "cancelled";
  value: number;
  notes?: string;
  is_dependent: boolean;
  patient_type: "convenio" | "private";
  location_name?: string;
};

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  is_default: boolean;
};

type EditConsultationModalProps = {
  isOpen: boolean;
  consultation: Consultation | null;
  onClose: () => void;
  onSuccess: () => void;
};

const EditConsultationModal: React.FC<EditConsultationModalProps> = ({
  isOpen,
  consultation,
  onClose,
  onSuccess,
}) => {
  const [attendanceLocations, setAttendanceLocations] = useState<
    AttendanceLocation[]
  >([]);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState("");
  const [slotDuration, setSlotDuration] = useState<SlotDuration>(30);

  // Form state
  const [formData, setFormData] = useState({
    date: "",
    time: "",
    value: "",
    location_id: "",
    notes: "",
    status: "scheduled" as
      | "scheduled"
      | "confirmed"
      | "completed"
      | "cancelled",
  });

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

  useEffect(() => {
    if (isOpen && consultation) {
      setFormData({
        date: utcToLocalDateInput(consultation.date),
        time: utcToLocalTimeInput(consultation.date),
        value: consultation.value.toString(),
        location_id: "", // Will be set after locations are loaded
        notes: consultation.notes || "",
        status: consultation.status,
      });

      fetchLocations();
    }
  }, [isOpen, consultation]);

  const fetchLocations = async () => {
    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/attendance-locations`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.ok) {
        const locationsData = await response.json();
        setAttendanceLocations(locationsData);

        // Try to match current location by name
        if (consultation?.location_name) {
          const matchingLocation = locationsData.find(
            (loc: AttendanceLocation) => loc.name === consultation.location_name
          );
          if (matchingLocation) {
            setFormData((prev) => ({
              ...prev,
              location_id: matchingLocation.id.toString(),
            }));
          }
        }
      }
    } catch (error) {
      console.error("Error fetching locations:", error);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    // Validate time format and slot
    const timeValidation = validateTimeSlot(formData.time, slotDuration);
    if (!timeValidation.isValid) {
      setError(timeValidation.error || "Horário inválido");
      return;
    }

    if (!consultation) return;

    try {
      setIsUpdating(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const dateTimeUTC = toUTCString(formData.date, formData.time);

      const updateData = {
        date: dateTimeUTC,
        value: Number.parseFloat(formData.value),
        location_id: formData.location_id
          ? Number.parseInt(formData.location_id)
          : null,
        notes:
          formData.notes && formData.notes.trim()
            ? formData.notes.trim()
            : null,
        status: formData.status,
      };

      const response = await fetch(
        `${apiUrl}/api/consultations/${consultation.id}`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(updateData),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Falha ao atualizar consulta");
      }

      onSuccess();
      onClose();
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao atualizar consulta"
      );
    } finally {
      setIsUpdating(false);
    }
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  const getStatusInfo = (status: string) => {
    switch (status) {
      case "scheduled":
        return { text: "Agendado", className: "bg-blue-100 text-blue-800" };
      case "confirmed":
        return { text: "Confirmado", className: "bg-green-100 text-green-800" };
      case "completed":
        return { text: "Concluído", className: "bg-gray-100 text-gray-800" };
      case "cancelled":
        return { text: "Cancelado", className: "bg-red-100 text-red-800" };
      default:
        return { text: "Desconhecido", className: "bg-gray-100 text-gray-800" };
    }
  };

  if (!isOpen || !consultation) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold flex items-center">
              <Calendar className="h-6 w-6 text-red-600 mr-2" />
              Editar Consulta
            </h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
              disabled={isUpdating}
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Consultation Info */}
        <div className="p-6 border-b border-gray-200 bg-gray-50">
          <div className="flex items-center mb-2">
            {consultation.is_dependent ? (
              <Users className="h-5 w-5 text-blue-600 mr-2" />
            ) : consultation.patient_type === "private" ? (
              <User className="h-5 w-5 text-purple-600 mr-2" />
            ) : (
              <User className="h-5 w-5 text-green-600 mr-2" />
            )}
            <span className="font-medium text-gray-900">
              {consultation.client_name}
            </span>
            {consultation.is_dependent && (
              <span className="ml-2 px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
                Dependente
              </span>
            )}
            {consultation.patient_type === "private" && (
              <span className="ml-2 px-2 py-1 bg-purple-100 text-purple-800 rounded-full text-xs">
                Particular
              </span>
            )}
          </div>
          <p className="text-sm text-gray-600">
            <strong>Serviço:</strong> {consultation.service_name}
          </p>
          <p className="text-sm text-gray-600">
            <strong>Status Atual:</strong>{" "}
            <span
              className={`px-2 py-1 rounded-full text-xs font-medium ${
                getStatusInfo(consultation.status).className
              }`}
            >
              {getStatusInfo(consultation.status).text}
            </span>
          </p>
        </div>

        {error && (
          <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg flex items-center">
            <AlertCircle className="h-5 w-5 mr-2" />
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="p-6">
          <div className="space-y-6">
            {/* Date and Time */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Data *
                </label>
                <input
                  type="date"
                  value={formData.date}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, date: e.target.value }))
                  }
                  className="input"
                  required
                />
              </div>

              <TimeInput
                value={formData.time}
                onChange={(time) => setFormData((prev) => ({ ...prev, time }))}
                label="Horário"
                required
                disabled={isUpdating}
              />
            </div>

            {/* Value and Location */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Valor (R$) *
                </label>
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={formData.value}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, value: e.target.value }))
                  }
                  className="input"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Local de Atendimento
                </label>
                <select
                  value={formData.location_id}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      location_id: e.target.value,
                    }))
                  }
                  className="input"
                >
                  <option value="">Selecione um local</option>
                  {attendanceLocations.map((location) => (
                    <option key={location.id} value={location.id.toString()}>
                      {location.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Status */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Status da Consulta *
              </label>
              <select
                value={formData.status}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    status: e.target.value as
                      | "scheduled"
                      | "confirmed"
                      | "completed"
                      | "cancelled",
                  }))
                }
                className="input"
                required
              >
                <option value="scheduled">Agendado</option>
                <option value="confirmed">Confirmado</option>
                <option value="completed">Concluído</option>
                <option value="cancelled">Cancelado</option>
              </select>
            </div>

            {/* Notes */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Observações
              </label>
              <textarea
                value={formData.notes}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, notes: e.target.value }))
                }
                className="input min-h-[80px]"
                placeholder="Observações sobre a consulta..."
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-secondary"
              disabled={isUpdating}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className={`btn btn-primary ${
                isUpdating ? "opacity-70 cursor-not-allowed" : ""
              }`}
              disabled={isUpdating}
            >
              {isUpdating ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                  Atualizando...
                </>
              ) : (
                <>
                  <Check className="h-5 w-5 mr-2" />
                  Salvar Alterações
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditConsultationModal;
