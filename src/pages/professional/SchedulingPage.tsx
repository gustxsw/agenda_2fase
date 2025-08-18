import React, { useState, useEffect } from "react";
import {
  Calendar,
  Clock,
  User,
  Plus,
  Check,
  X,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Users,
  Edit2,
  CheckCircle,
  XCircle,
  PlayCircle,
} from "lucide-react";
import { format, addDays, subDays, isSameDay } from "date-fns";
import { ptBR } from "date-fns/locale";

type Appointment = {
  id: number;
  date: string;
  time: string;
  client_name: string;
  service_name: string;
  status: "scheduled" | "confirmed" | "completed" | "cancelled";
  value: number;
  notes?: string;
  is_dependent: boolean;
};

type Service = {
  id: number;
  name: string;
  base_price: number;
};

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  is_default: boolean;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

const SchedulingPage: React.FC = () => {
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [attendanceLocations, setAttendanceLocations] = useState<AttendanceLocation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // New appointment modal
  const [showNewModal, setShowNewModal] = useState(false);
  const [isCreating, setIsCreating] = useState(false);

  // Status change modal
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [selectedAppointment, setSelectedAppointment] =
    useState<Appointment | null>(null);
  const [newStatus, setNewStatus] = useState<
    "scheduled" | "confirmed" | "completed" | "cancelled"
  >("scheduled");
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    patient_type: "convenio",
    client_cpf: "",
    private_patient_id: "",
    date: format(new Date(), "yyyy-MM-dd"),
    time: "",
    service_id: "",
    value: "",
    location_id: "",
    notes: "",
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
    fetchData();
  }, [selectedDate]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const dateStr = format(selectedDate, "yyyy-MM-dd");

      console.log("🔄 Fetching appointments for date:", dateStr);

      // Fetch appointments
      const appointmentsResponse = await fetch(`${apiUrl}/api/consultations`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
      });

      if (appointmentsResponse.ok) {
        const appointmentsData = await appointmentsResponse.json();
        console.log("✅ Raw appointments data:", appointmentsData);

        // Filter by selected date and convert to appointment format
        const filteredAppointments = appointmentsData
          .filter((consultation: any) => {
            const consultationDate = new Date(consultation.date);
            return isSameDay(consultationDate, selectedDate);
          })
          .map((consultation: any) => ({
            id: consultation.id,
            date: consultation.date,
            time: format(new Date(consultation.date), "HH:mm"),
            client_name: consultation.client_name,
            service_name: consultation.service_name,
            status: consultation.status || "completed", // Default to completed for existing consultations
            value: consultation.value,
            notes: consultation.notes || "",
            is_dependent: consultation.is_dependent || false,
          }));

        console.log("✅ Processed appointments:", filteredAppointments);
        setAppointments(filteredAppointments);
      } else {
        console.error("Appointments response error:", appointmentsResponse.status);
      }

      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
      });

      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        console.log("Services loaded:", servicesData.length);
        setServices(servicesData);
      } else {
        console.error("Services response error:", servicesResponse.status);
      }

      // Fetch private patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        console.log("Private patients loaded:", patientsData.length);
        setPrivatePatients(Array.isArray(patientsData) ? patientsData : []);
      } else {
        console.error("Private patients response error:", patientsResponse.status);
        setPrivatePatients([]);
      }

      // Fetch attendance locations
      const locationsResponse = await fetch(`${apiUrl}/api/attendance-locations`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
      });

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        console.log("Attendance locations loaded:", locationsData.length);
        setAttendanceLocations(locationsData);
        
        // Set default location if exists
        const defaultLocation = locationsData.find((loc: AttendanceLocation) => loc.is_default);
        if (defaultLocation) {
          setFormData(prev => ({ ...prev, location_id: defaultLocation.id.toString() }));
        }
      } else {
        console.error("Attendance locations response error:", locationsResponse.status);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      setError("Não foi possível carregar os dados da agenda");
    } finally {
      setIsLoading(false);
    }
  };

  const createAppointment = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setIsCreating(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      let clientData = null;

      // Se for convênio, buscar cliente por CPF
      if (formData.patient_type === "convenio") {
        const clientResponse = await fetch(
          `${apiUrl}/api/clients/lookup?cpf=${formData.client_cpf.replace(
            /\D/g,
            ""
          )}`,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );

        if (!clientResponse.ok) {
          throw new Error("Cliente não encontrado");
        }

        clientData = await clientResponse.json();

        if (clientData.subscription_status !== "active") {
          throw new Error("Cliente não possui assinatura ativa");
        }
      }

      // Criar consulta com status inicial 'scheduled'
      const consultationData = {
        client_id: formData.patient_type === "convenio" ? clientData.id : null,
        private_patient_id:
          formData.patient_type === "private"
            ? parseInt(formData.private_patient_id)
            : null,
        service_id: parseInt(formData.service_id),
        location_id: formData.location_id ? parseInt(formData.location_id) : null,
        value: parseFloat(formData.value),
        date: new Date(`${formData.date}T${formData.time}`).toISOString(),
        status: "scheduled", // Status inicial
        notes: formData.notes,
      };

      console.log("🔄 Creating consultation:", consultationData);

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
        throw new Error(errorData.message || "Falha ao criar agendamento");
      }

      await fetchData();
      setShowNewModal(false);
      setFormData({
        patient_type: "convenio",
        client_cpf: "",
        private_patient_id: "",
        date: format(selectedDate, "yyyy-MM-dd"),
        time: "",
        service_id: "",
        value: "",
        location_id: "",
        notes: "",
      });
      setSuccess("Agendamento criado com sucesso!");
      setTimeout(() => setSuccess(""), 3000);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao criar agendamento"
      );
    } finally {
      setIsCreating(false);
    }
  };

  const openStatusModal = (appointment: Appointment) => {
    console.log("🔄 Opening status modal for appointment:", appointment);
    setSelectedAppointment(appointment);
    setNewStatus(appointment.status);
    setShowStatusModal(true);
  };

  const closeStatusModal = () => {
    setShowStatusModal(false);
    setSelectedAppointment(null);
    setError("");
  };

  const updateAppointmentStatus = async () => {
    if (!selectedAppointment) return;

    try {
      setIsUpdatingStatus(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Updating appointment status:", {
        id: selectedAppointment.id,
        newStatus,
        currentStatus: selectedAppointment.status,
      });

      const response = await fetch(
        `${apiUrl}/api/consultations/${selectedAppointment.id}/status`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ status: newStatus }),
        }
      );

      console.log("📡 Status update response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Status update error:", errorData);
        throw new Error(errorData.message || "Erro ao atualizar status");
      }

      const responseData = await response.json();
      console.log("✅ Status update response:", responseData);

      console.log("✅ Status updated successfully");

      await fetchData();
      setShowStatusModal(false);
      setSelectedAppointment(null);
      setSuccess("Status atualizado com sucesso!");
      setTimeout(() => setSuccess(""), 3000);
    } catch (error) {
      console.error("❌ Error updating status:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao atualizar status"
      );
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const getStatusInfo = (status: string) => {
    switch (status) {
      case "scheduled":
        return {
          text: "Agendado",
          className: "bg-blue-100 text-blue-800 border-blue-200",
          icon: <Clock className="h-3 w-3 mr-1" />,
        };
      case "confirmed":
        return {
          text: "Confirmado",
          className: "bg-green-100 text-green-800 border-green-200",
          icon: <CheckCircle className="h-3 w-3 mr-1" />,
        };
      case "completed":
        return {
          text: "Concluído",
          className: "bg-gray-100 text-gray-800 border-gray-200",
          icon: <Check className="h-3 w-3 mr-1" />,
        };
      case "cancelled":
        return {
          text: "Cancelado",
          className: "bg-red-100 text-red-800 border-red-200",
          icon: <XCircle className="h-3 w-3 mr-1" />,
        };
      default:
        return {
          text: "Desconhecido",
          className: "bg-gray-100 text-gray-800 border-gray-200",
          icon: <AlertCircle className="h-3 w-3 mr-1" />,
        };
    }
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  const formatCpf = (value: string) => {
    if (!value) return '';
    const numericValue = value.replace(/\D/g, "");
    return numericValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData((prev) => ({ ...prev, service_id: serviceId }));

    // Auto-fill value based on service
    const service = services.find((s) => s.id.toString() === serviceId);
    if (service) {
      setFormData((prev) => ({
        ...prev,
        value: service.base_price.toString(),
      }));
    }
  };

  const generateTimeSlots = () => {
    const slots = [];
    for (let hour = 8; hour <= 18; hour++) {
      for (let minute = 0; minute < 60; minute += 30) {
        const timeStr = `${hour.toString().padStart(2, "0")}:${minute
          .toString()
          .padStart(2, "0")}`;
        slots.push(timeStr);
      }
    }
    return slots;
  };

  const timeSlots = generateTimeSlots();
  const dailyAppointments = appointments.sort((a, b) =>
    a.time.localeCompare(b.time)
  );

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda</h1>
          <p className="text-gray-600">
            Visualize e gerencie seus agendamentos
          </p>
        </div>

        <button
          onClick={() => setShowNewModal(true)}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Nova Consulta
        </button>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6 flex items-center">
          <Check className="h-5 w-5 mr-2" />
          {success}
        </div>
      )}

      {/* Navegação de Data */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setSelectedDate(subDays(selectedDate, 1))}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>

          <div className="text-center">
            <h2 className="text-xl font-semibold text-gray-900">
              {format(selectedDate, "EEEE, dd 'de' MMMM", { locale: ptBR })}
            </h2>
            <p className="text-sm text-gray-600">
              {dailyAppointments.length} agendamento(s)
            </p>
          </div>

          <button
            onClick={() => setSelectedDate(addDays(selectedDate, 1))}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        </div>

        <div className="flex justify-center mt-4">
          <button
            onClick={() => setSelectedDate(new Date())}
            className="btn btn-secondary"
          >
            Hoje
          </button>
        </div>
      </div>

      {/* Lista de Agendamentos */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando agendamentos...</p>
          </div>
        ) : dailyAppointments.length === 0 ? (
          <div className="text-center py-12">
            <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              Nenhum agendamento para este dia
            </h3>
            <p className="text-gray-600 mb-4">
              Sua agenda está livre para{" "}
              {format(selectedDate, "dd 'de' MMMM", { locale: ptBR })}
            </p>
            <button
              onClick={() => setShowNewModal(true)}
              className="btn btn-primary inline-flex items-center"
            >
              <Plus className="h-5 w-5 mr-2" />
              Criar Agendamento
            </button>
          </div>
        ) : (
          <div className="flex">
            {/* Coluna de Horários */}
            <div className="w-24 bg-gray-50 border-r border-gray-200">
              <div className="sticky top-0 bg-gray-100 p-3 border-b border-gray-200">
                <div className="text-xs font-medium text-gray-600 text-center">
                  HORÁRIO
                </div>
              </div>
              <div className="space-y-0">
                {timeSlots.map((timeSlot) => (
                  <div
                    key={timeSlot}
                    className="h-16 flex items-center justify-center border-b border-gray-100 text-sm font-medium text-gray-700"
                  >
                    {timeSlot}
                  </div>
                ))}
              </div>
            </div>

            {/* Coluna de Agendamentos */}
            <div className="flex-1">
              <div className="sticky top-0 bg-gray-100 p-3 border-b border-gray-200">
                <div className="text-xs font-medium text-gray-600 text-center">
                  AGENDAMENTOS
                </div>
              </div>
              <div className="relative">
                {timeSlots.map((timeSlot) => {
                  const appointment = dailyAppointments.find(
                    (apt) => apt.time === timeSlot
                  );
                  
                  return (
                    <div
                      key={timeSlot}
                      className="h-16 border-b border-gray-100 flex items-center px-4 hover:bg-gray-50 transition-colors"
                    >
                      {appointment ? (
                        <div className="flex items-center justify-between w-full">
                          <div className="flex items-center space-x-3 flex-1">
                            {/* Informações do paciente */}
                            <div className="flex-1">
                              <div className="flex items-center mb-1">
                                {appointment.is_dependent ? (
                                  <Users className="h-4 w-4 text-blue-600 mr-2" />
                                ) : (
                                  <User className="h-4 w-4 text-green-600 mr-2" />
                                )}
                                <span className="font-medium text-gray-900 text-sm">
                                  {appointment.client_name}
                                </span>
                                {appointment.is_dependent && (
                                  <span className="ml-2 px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
                                    Dependente
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center space-x-4">
                                <p className="text-xs text-gray-600">
                                  {appointment.service_name}
                                </p>
                                <p className="text-xs font-medium text-green-600">
                                  {formatCurrency(appointment.value)}
                                </p>
                              </div>
                              {appointment.notes && (
                                <p className="text-xs text-gray-500 mt-1 italic truncate">
                                  "{appointment.notes}"
                                </p>
                              )}
                            </div>
                          </div>

                          {/* Status */}
                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => openStatusModal(appointment)}
                              className={`px-2 py-1 rounded text-xs font-medium flex items-center border transition-all hover:shadow-sm ${getStatusInfo(appointment.status).className}`}
                              title="Clique para alterar o status"
                            >
                              {getStatusInfo(appointment.status).icon}
                              {getStatusInfo(appointment.status).text}
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="text-xs text-gray-400 italic">
                          Horário livre
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Estatísticas do Dia */}
      {dailyAppointments.length > 0 && (
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-blue-50 p-4 rounded-lg text-center border border-blue-200">
            <div className="text-2xl font-bold text-blue-600">
              {dailyAppointments.filter((a) => a.status === "scheduled").length}
            </div>
            <div className="text-sm text-blue-700 flex items-center justify-center">
              <Clock className="h-3 w-3 mr-1" />
              Agendados
            </div>
          </div>

          <div className="bg-green-50 p-4 rounded-lg text-center border border-green-200">
            <div className="text-2xl font-bold text-green-600">
              {dailyAppointments.filter((a) => a.status === "confirmed").length}
            </div>
            <div className="text-sm text-green-700 flex items-center justify-center">
              <CheckCircle className="h-3 w-3 mr-1" />
              Confirmados
            </div>
          </div>

          <div className="bg-gray-50 p-4 rounded-lg text-center border border-gray-200">
            <div className="text-2xl font-bold text-gray-600">
              {dailyAppointments.filter((a) => a.status === "completed").length}
            </div>
            <div className="text-sm text-gray-700 flex items-center justify-center">
              <Check className="h-3 w-3 mr-1" />
              Concluídos
            </div>
          </div>

          <div className="bg-red-50 p-4 rounded-lg text-center border border-red-200">
            <div className="text-2xl font-bold text-red-600">
              {dailyAppointments.filter((a) => a.status === "cancelled").length}
            </div>
            <div className="text-sm text-red-700 flex items-center justify-center">
              <XCircle className="h-3 w-3 mr-1" />
              Cancelados
            </div>
          </div>
        </div>
      )}

      {/* Modal de Nova Consulta */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold flex items-center">
                  <Plus className="h-6 w-6 text-red-600 mr-2" />
                  Nova Consulta
                </h2>
                <button
                  onClick={() => setShowNewModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                {error}
              </div>
            )}

            <form onSubmit={createAppointment} className="p-6">
              <div className="space-y-4">
                {/* Tipo de Paciente */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tipo de Paciente *
                  </label>
                  <select
                    value={formData.patient_type}
                    onChange={(e) =>
                      setFormData((prev) => ({
                        ...prev,
                        patient_type: e.target.value,
                        client_cpf: "",
                        private_patient_id: "",
                      }))
                    }
                    className="input"
                    required
                  >
                    <option value="convenio">Cliente do Convênio</option>
                    <option value="private">Paciente Particular</option>
                  </select>
                </div>

                {/* Cliente do Convênio */}
                {formData.patient_type === "convenio" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      CPF do Cliente *
                    </label>
                    <input
                      type="text"
                      value={formatCpf(formData.client_cpf)}
                      onChange={(e) =>
                        setFormData((prev) => ({
                          ...prev,
                          client_cpf: e.target.value.replace(/\D/g, ""),
                        }))
                      }
                      className="input"
                      placeholder="000.000.000-00"
                      required
                    />
                  </div>
                )}

                {/* Paciente Particular */}
                {formData.patient_type === "private" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Paciente Particular *
                    </label>
                    <select
                      value={formData.private_patient_id}
                      onChange={(e) =>
                        setFormData((prev) => ({
                          ...prev,
                          private_patient_id: e.target.value,
                        }))
                      }
                      className="input"
                      required
                    >
                      <option value="">Selecione um paciente</option>
                      {privatePatients.map((patient) => (
                        <option key={patient.id} value={patient.id}>
                          {patient.name} - {patient.cpf ? formatCpf(patient.cpf) : 'CPF não informado'}
                        </option>
                      ))}
                    </select>
                    {privatePatients.length === 0 && (
                      <p className="text-sm text-gray-500 mt-1">
                        Nenhum paciente particular cadastrado. Cadastre pacientes na seção "Pacientes Particulares".
                      </p>
                    )}
                  </div>
                )}

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

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Horário *
                  </label>
                  <select
                    value={formData.time}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, time: e.target.value }))
                    }
                    className="input"
                    required
                  >
                    <option value="">Selecione um horário</option>
                    {timeSlots.map((time) => (
                      <option key={time} value={time}>
                        {time}
                      </option>
                    ))}
                  </select>
                </div>

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
                      </option>
                    ))}
                  </select>
                </div>

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
                    value={formData.location_id || ''}
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
                  {attendanceLocations.length === 0 && (
                    <p className="text-sm text-gray-500 mt-1">
                      Configure seus locais de atendimento no perfil.
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações
                  </label>
                  <textarea
                    value={formData.notes}
                    onChange={(e) =>
                      setFormData((prev) => ({
                        ...prev,
                        notes: e.target.value,
                      }))
                    }
                    className="input min-h-[80px]"
                    placeholder="Observações sobre a consulta..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
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
                  disabled={isCreating}
                >
                  {isCreating ? "Criando..." : "Agendar Consulta"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal de Alteração de Status */}
      {showStatusModal && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold flex items-center">
                  <Edit2 className="h-6 w-6 text-blue-600 mr-2" />
                  Alterar Status
                </h2>
                <button
                  onClick={closeStatusModal}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                {error}
              </div>
            )}

            <div className="p-6">
              {/* Informações do agendamento */}
              <div className="bg-gray-50 p-4 rounded-lg mb-6">
                <div className="flex items-center mb-2">
                  {selectedAppointment.is_dependent ? (
                    <Users className="h-4 w-4 text-blue-600 mr-2" />
                  ) : (
                    <User className="h-4 w-4 text-green-600 mr-2" />
                  )}
                  <span className="font-medium">
                    {selectedAppointment.client_name}
                  </span>
                </div>
                <p className="text-sm text-gray-600 mb-1">
                  <strong>Serviço:</strong> {selectedAppointment.service_name}
                </p>
                <p className="text-sm text-gray-600 mb-1">
                  <strong>Data/Hora:</strong>{" "}
                  {format(
                    new Date(selectedAppointment.date),
                    "dd/MM/yyyy 'às' HH:mm"
                  )}
                </p>
                <p className="text-sm text-gray-600">
                  <strong>Valor:</strong>{" "}
                  {formatCurrency(selectedAppointment.value)}
                </p>
              </div>

              {/* Seleção de novo status */}
              <div className="space-y-3">
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  Selecione o novo status:
                </label>

                <div className="space-y-2">
                  <label
                    className={`flex items-center p-3 border-2 rounded-lg cursor-pointer transition-all ${
                      newStatus === "scheduled"
                        ? "border-blue-300 bg-blue-50"
                        : "border-gray-200 hover:bg-gray-50"
                    }`}
                  >
                    <input
                      type="radio"
                      name="status"
                      value="scheduled"
                      checked={newStatus === "scheduled"}
                      onChange={(e) => setNewStatus(e.target.value as any)}
                      className="text-blue-600 focus:ring-blue-500"
                    />
                    <div className="ml-3 flex items-center">
                      <Clock className="h-4 w-4 text-blue-600 mr-2" />
                      <div>
                        <div className="font-medium text-gray-900">
                          Agendado
                        </div>
                        <div className="text-sm text-gray-500">
                          Consulta marcada
                        </div>
                      </div>
                    </div>
                  </label>

                  <label
                    className={`flex items-center p-3 border-2 rounded-lg cursor-pointer transition-all ${
                      newStatus === "confirmed"
                        ? "border-green-300 bg-green-50"
                        : "border-gray-200 hover:bg-gray-50"
                    }`}
                  >
                    <input
                      type="radio"
                      name="status"
                      value="confirmed"
                      checked={newStatus === "confirmed"}
                      onChange={(e) => setNewStatus(e.target.value as any)}
                      className="text-green-600 focus:ring-green-500"
                    />
                    <div className="ml-3 flex items-center">
                      <CheckCircle className="h-4 w-4 text-green-600 mr-2" />
                      <div>
                        <div className="font-medium text-gray-900">
                          Confirmado
                        </div>
                        <div className="text-sm text-gray-500">
                          Paciente confirmou
                        </div>
                      </div>
                    </div>
                  </label>

                  <label
                    className={`flex items-center p-3 border-2 rounded-lg cursor-pointer transition-all ${
                      newStatus === "completed"
                        ? "border-gray-300 bg-gray-50"
                        : "border-gray-200 hover:bg-gray-50"
                    }`}
                  >
                    <input
                      type="radio"
                      name="status"
                      value="completed"
                      checked={newStatus === "completed"}
                      onChange={(e) => setNewStatus(e.target.value as any)}
                      className="text-gray-600 focus:ring-gray-500"
                    />
                    <div className="ml-3 flex items-center">
                      <Check className="h-4 w-4 text-gray-600 mr-2" />
                      <div>
                        <div className="font-medium text-gray-900">
                          Concluído
                        </div>
                        <div className="text-sm text-gray-500">
                          Consulta realizada
                        </div>
                      </div>
                    </div>
                  </label>

                  <label
                    className={`flex items-center p-3 border-2 rounded-lg cursor-pointer transition-all ${
                      newStatus === "cancelled"
                        ? "border-red-300 bg-red-50"
                        : "border-gray-200 hover:bg-gray-50"
                    }`}
                  >
                    <input
                      type="radio"
                      name="status"
                      value="cancelled"
                      checked={newStatus === "cancelled"}
                      onChange={(e) => setNewStatus(e.target.value as any)}
                      className="text-red-600 focus:ring-red-500"
                    />
                    <div className="ml-3 flex items-center">
                      <XCircle className="h-4 w-4 text-red-600 mr-2" />
                      <div>
                        <div className="font-medium text-gray-900">
                          Cancelado
                        </div>
                        <div className="text-sm text-gray-500">
                          Consulta cancelada
                        </div>
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={closeStatusModal}
                  className="btn btn-secondary"
                  disabled={isUpdatingStatus}
                >
                  Cancelar
                </button>
                <button
                  onClick={updateAppointmentStatus}
                  className={`btn btn-primary ${
                    isUpdatingStatus ? "opacity-70 cursor-not-allowed" : ""
                  }`}
                  disabled={
                    isUpdatingStatus || newStatus === selectedAppointment.status
                  }
                >
                  {isUpdatingStatus ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Atualizando...
                    </>
                  ) : (
                    <>
                      <Check className="h-4 w-4 mr-2" />
                      Atualizar Status
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;
