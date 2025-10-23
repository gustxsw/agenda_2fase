import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import {
  Calendar,
  Clock,
  User,
  Users,
  X,
  Check,
  AlertCircle,
  Search,
} from "lucide-react";
import { toUTCString } from "../utils/dateHelpers";
import { getApiUrl } from "../utils/apiHelpers";
import ScheduleConflictModal from "./ScheduleConflictModal";

type Service = {
  id: number;
  name: string;
  base_price: number;
  category_name: string;
};

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  is_default: boolean;
};

type Client = {
  id: number;
  name: string;
  cpf: string;
  subscription_status: string;
};

type Dependent = {
  id: number;
  name: string;
  cpf: string;
  client_id: number;
  client_name: string;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

type QuickScheduleModalProps = {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  selectedSlot: {
    date: string;
    time: string;
  } | null;
};

const QuickScheduleModal: React.FC<QuickScheduleModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  selectedSlot,
}) => {
  const { user } = useAuth();
  const [services, setServices] = useState<Service[]>([]);
  const [attendanceLocations, setAttendanceLocations] = useState<
    AttendanceLocation[]
  >([]);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState("");

  const [showConflictModal, setShowConflictModal] = useState(false);
  const [conflictData, setConflictData] = useState<
    Array<{
      date: string;
      time: string;
      clientName: string;
    }>
  >([]);

  const [patientType, setPatientType] = useState<"convenio" | "private">(
    "convenio"
  );
  const [searchCpf, setSearchCpf] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [foundClient, setFoundClient] = useState<Client | null>(null);
  const [foundDependent, setFoundDependent] = useState<Dependent | null>(null);
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [selectedDependentId, setSelectedDependentId] = useState<number | null>(
    null
  );
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);

  const [privatePatientSearch, setPrivatePatientSearch] = useState("");
  const [filteredPrivatePatients, setFilteredPrivatePatients] = useState<
    PrivatePatient[]
  >([]);
  const [showPrivatePatientDropdown, setShowPrivatePatientDropdown] =
    useState(false);

  const [formData, setFormData] = useState({
    service_id: "",
    value: "",
    location_id: "",
    notes: "",
    private_patient_id: "",
  });

  useEffect(() => {
    if (isOpen) {
      fetchData();
      resetForm();
    }
  }, [isOpen]);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        setServices(servicesData);
      }

      const locationsResponse = await fetch(
        `${apiUrl}/api/attendance-locations`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        setAttendanceLocations(locationsData);

        const defaultLocation = locationsData.find(
          (loc: AttendanceLocation) => loc.is_default
        );
        if (defaultLocation) {
          setFormData((prev) => ({
            ...prev,
            location_id: defaultLocation.id.toString(),
          }));
        }
      }

      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        setPrivatePatients(patientsData);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      setError("Não foi possível carregar os dados necessários");
    }
  };

  const resetForm = () => {
    setSearchCpf("");
    setFoundClient(null);
    setFoundDependent(null);
    setDependents([]);
    setSelectedDependentId(null);
    setPrivatePatientSearch("");
    setShowPrivatePatientDropdown(false);
    setFormData({
      service_id: "",
      value: "",
      location_id: "",
      notes: "",
      private_patient_id: "",
    });
    setError("");
    setConflictData([]);
    setShowConflictModal(false);
  };

  const searchByCpf = async () => {
    if (!searchCpf) return;

    try {
      setIsSearching(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const cleanCpf = searchCpf.replace(/\D/g, "");

      const dependentResponse = await fetch(
        `${apiUrl}/api/dependents/search?cpf=${cleanCpf}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (dependentResponse.ok) {
        const dependentData = await dependentResponse.json();

        if (dependentData.status !== "active") {
          setError("Este dependente não possui assinatura ativa.");
          return;
        }

        setFoundDependent(dependentData);
        setFoundClient(null);
        setDependents([]);
        setSelectedDependentId(dependentData.id);
        return;
      }

      const clientResponse = await fetch(
        `${apiUrl}/api/clients/lookup?cpf=${cleanCpf}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!clientResponse.ok) {
        if (clientResponse.status === 404) {
          setError("Cliente ou dependente não encontrado.");
        } else {
          setError("Erro ao buscar cliente.");
        }
        return;
      }

      const clientData = await clientResponse.json();

      if (clientData.subscription_status !== "active") {
        setError("Este cliente não possui assinatura ativa.");
        return;
      }

      setFoundClient(clientData);
      setFoundDependent(null);
      setSelectedDependentId(null);

      const dependentsResponse = await fetch(
        `${apiUrl}/api/dependents?client_id=${clientData.id}&status=active`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (dependentsResponse.ok) {
        const dependentsData = await dependentsResponse.json();
        setDependents(dependentsData);
      }
    } catch (error) {
      setError("Erro ao buscar paciente.");
    } finally {
      setIsSearching(false);
    }
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData((prev) => ({ ...prev, service_id: serviceId }));

    const service = services.find((s) => s.id.toString() === serviceId);
    if (service) {
      setFormData((prev) => ({
        ...prev,
        value: service.base_price.toString(),
      }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setShowConflictModal(false);
    setConflictData([]);

    if (!selectedSlot) return;

    if (patientType === "convenio") {
      if (!foundClient && !foundDependent) {
        setError("Busque e selecione um cliente ou dependente");
        return;
      }
    } else {
      if (!formData.private_patient_id) {
        setError("Selecione um paciente particular");
        return;
      }
    }

    try {
      setIsCreating(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const dateTimeUTC = toUTCString(selectedSlot.date, selectedSlot.time);

      const consultationData: any = {
        professional_id: user?.id,
        service_id: Number.parseInt(formData.service_id),
        location_id: formData.location_id
          ? Number.parseInt(formData.location_id)
          : null,
        value: Number.parseFloat(formData.value),
        date: dateTimeUTC,
        status: "scheduled",
        notes: formData.notes.trim() || null,
      };

      if (patientType === "private") {
        consultationData.private_patient_id = Number.parseInt(
          formData.private_patient_id || ""
        );
      } else {
        if (foundDependent) {
          consultationData.dependent_id = foundDependent.id;
        } else if (selectedDependentId) {
          consultationData.dependent_id = selectedDependentId;
        } else if (foundClient) {
          consultationData.user_id = foundClient.id;
        }
      }

      console.log("🔄 Quick schedule consultation data:", consultationData);
      const response = await fetch(`${apiUrl}/api/consultations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(consultationData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Quick schedule error:", errorData);
        if (
          response.status === 409 &&
          errorData.conflict &&
          errorData.conflictDetails
        ) {
          setConflictData([errorData.conflictDetails]);
          setShowConflictModal(true);
          setError("");
        } else {
          setError(errorData.message || "Falha ao agendar consulta");
        }
        return;
      }

      onSuccess();
      onClose();
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao agendar consulta"
      );
    } finally {
      setIsCreating(false);
    }
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    return numericValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  useEffect(() => {
    if (privatePatientSearch.trim() === "") {
      setFilteredPrivatePatients(privatePatients);
    } else {
      const searchLower = privatePatientSearch.toLowerCase();
      const filtered = privatePatients.filter(
        (patient) =>
          patient.name.toLowerCase().includes(searchLower) ||
          (patient.cpf && patient.cpf.includes(searchLower.replace(/\D/g, "")))
      );
      setFilteredPrivatePatients(filtered);
    }
  }, [privatePatientSearch, privatePatients]);

  const handlePrivatePatientSelect = (patient: PrivatePatient) => {
    setFormData((prev) => ({
      ...prev,
      private_patient_id: patient.id.toString(),
    }));
    setPrivatePatientSearch(patient.name);
    setShowPrivatePatientDropdown(false);
  };

  if (!isOpen || !selectedSlot) return null;

  return (
    <>
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
          <div className="p-6 border-b border-gray-200">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-bold flex items-center">
                <Calendar className="h-6 w-6 text-red-600 mr-2" />
                Agendar Consulta
              </h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600"
                disabled={isCreating}
              >
                <X className="h-6 w-6" />
              </button>
            </div>
          </div>

          <div className="p-6 border-b border-gray-200 bg-blue-50">
            <div className="flex items-center">
              <Clock className="h-5 w-5 text-blue-600 mr-2" />
              <div>
                <p className="font-medium text-blue-900">
                  {new Date(selectedSlot.date).toLocaleDateString("pt-BR", {
                    weekday: "long",
                    day: "2-digit",
                    month: "long",
                    year: "numeric",
                  })}
                </p>
                <p className="text-sm text-blue-700">
                  Horário: {selectedSlot.time}
                </p>
              </div>
            </div>
          </div>

          {error && (
            <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg flex items-center">
              <AlertCircle className="h-5 w-5 mr-2" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="p-6">
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Tipo de Paciente *
                </label>
                <select
                  value={patientType}
                  onChange={(e) => {
                    setPatientType(e.target.value as "convenio" | "private");
                    resetForm();
                  }}
                  className="input"
                  required
                >
                  <option value="convenio">Cliente do Convênio</option>
                  <option value="private">Paciente Particular</option>
                </select>
              </div>

              {patientType === "convenio" && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Buscar por CPF *
                  </label>
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={formatCpf(searchCpf)}
                      onChange={(e) =>
                        setSearchCpf(e.target.value.replace(/\D/g, ""))
                      }
                      className="input flex-1"
                      placeholder="000.000.000-00"
                    />
                    <button
                      type="button"
                      onClick={searchByCpf}
                      className="btn btn-secondary"
                      disabled={isSearching || !searchCpf}
                    >
                      {isSearching ? "Buscando..." : "Buscar"}
                    </button>
                  </div>

                  {foundClient && (
                    <div className="mt-3 p-3 bg-green-50 rounded-lg border border-green-200">
                      <div className="flex items-center mb-2">
                        <User className="h-4 w-4 text-green-600 mr-2" />
                        <span className="font-medium text-green-800">
                          Cliente: {foundClient.name}
                        </span>
                      </div>

                      {dependents.length > 0 && (
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Dependente (opcional)
                          </label>
                          <select
                            value={selectedDependentId || ""}
                            onChange={(e) =>
                              setSelectedDependentId(
                                e.target.value ? Number(e.target.value) : null
                              )
                            }
                            className="input"
                          >
                            <option value="">Consulta para o titular</option>
                            {dependents.map((dependent) => (
                              <option key={dependent.id} value={dependent.id}>
                                {dependent.name}
                              </option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                  )}

                  {foundDependent && (
                    <div className="mt-3 p-3 bg-blue-50 rounded-lg border border-blue-200">
                      <div className="flex items-center">
                        <Users className="h-4 w-4 text-blue-600 mr-2" />
                        <div>
                          <span className="font-medium text-blue-800">
                            Dependente: {foundDependent.name}
                          </span>
                          <p className="text-sm text-blue-700">
                            Titular: {foundDependent.client_name}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {patientType === "private" && (
                <div className="relative">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Paciente Particular *
                  </label>
                  <div className="relative">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                      <input
                        type="text"
                        value={privatePatientSearch}
                        onChange={(e) => {
                          setPrivatePatientSearch(e.target.value);
                          setShowPrivatePatientDropdown(true);
                        }}
                        onFocus={() => setShowPrivatePatientDropdown(true)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                        placeholder="Digite o nome ou CPF do paciente..."
                        required={!formData.private_patient_id}
                      />
                    </div>

                    {showPrivatePatientDropdown &&
                      filteredPrivatePatients.length > 0 && (
                        <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                          {filteredPrivatePatients.map((patient) => (
                            <button
                              key={patient.id}
                              type="button"
                              onClick={() =>
                                handlePrivatePatientSelect(patient)
                              }
                              className={`w-full text-left px-4 py-3 hover:bg-blue-50 transition-colors border-b border-gray-100 last:border-b-0 ${
                                formData.private_patient_id ===
                                patient.id.toString()
                                  ? "bg-blue-50"
                                  : ""
                              }`}
                            >
                              <div className="font-medium text-gray-900">
                                {patient.name}
                              </div>
                              <div className="text-sm text-gray-500">
                                {patient.cpf
                                  ? formatCpf(patient.cpf)
                                  : "CPF não informado"}
                              </div>
                            </button>
                          ))}
                        </div>
                      )}

                    {showPrivatePatientDropdown &&
                      privatePatientSearch.trim() !== "" &&
                      filteredPrivatePatients.length === 0 && (
                        <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg p-4">
                          <p className="text-sm text-gray-500 text-center">
                            Nenhum paciente encontrado
                          </p>
                        </div>
                      )}
                  </div>

                  {formData.private_patient_id && (
                    <div className="mt-2 p-3 bg-green-50 rounded-lg border border-green-200 flex items-center justify-between">
                      <div className="flex items-center">
                        <User className="h-4 w-4 text-green-600 mr-2" />
                        <span className="text-sm font-medium text-green-800">
                          {
                            privatePatients.find(
                              (p) =>
                                p.id.toString() === formData.private_patient_id
                            )?.name
                          }
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setFormData((prev) => ({
                            ...prev,
                            private_patient_id: "",
                          }));
                          setPrivatePatientSearch("");
                        }}
                        className="text-green-600 hover:text-green-800"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Serviço *
                </label>
                <select
                  value={formData.service_id}
                  onChange={handleServiceChange}
                  className="input"
                  required
                >
                  <option value="">Selecione um serviço</option>
                  {services.map((service) => (
                    <option key={service.id} value={service.id}>
                      {service.name} - {formatCurrency(service.base_price)}
                      {service.category_name && ` (${service.category_name})`}
                    </option>
                  ))}
                </select>
              </div>

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
                      setFormData((prev) => ({
                        ...prev,
                        value: e.target.value,
                      }))
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
                      <option key={location.id} value={location.id}>
                        {location.name} {location.is_default && "(Padrão)"}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

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
                disabled={isCreating}
              >
                Cancelar
              </button>
              <button
                type="submit"
                className={`btn btn-primary ${
                  isCreating ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={
                  isCreating ||
                  (patientType === "convenio" &&
                    !foundClient &&
                    !foundDependent) ||
                  (patientType === "private" && !formData.private_patient_id) ||
                  !formData.service_id ||
                  !formData.value
                }
              >
                {isCreating ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Agendando...
                  </>
                ) : (
                  <>
                    <Check className="h-5 w-5 mr-2" />
                    Agendar Consulta
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </div>

      <ScheduleConflictModal
        isOpen={showConflictModal}
        onClose={() => setShowConflictModal(false)}
        conflicts={conflictData}
        isSingleConflict={true}
      />
    </>
  );
};

export default QuickScheduleModal;
