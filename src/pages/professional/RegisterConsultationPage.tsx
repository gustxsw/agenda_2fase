import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import TimeInput from "../../components/TimeInput";
import {
  validateTimeSlot,
  type SlotDuration,
} from "../../utils/timeSlotValidation";
import { Search, Calendar, User, Users, AlertTriangle } from "lucide-react";

type Service = {
  id: number;
  name: string;
  base_price: number;
  category_id: number;
  category_name: string;
  is_base_service: boolean;
};

type Category = {
  id: number;
  name: string;
  description: string;
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
  birth_date: string;
  client_id: number;
  client_name: string;
  client_subscription_status: string;
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

const RegisterConsultationPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Patient type selection
  // 🔥 FIXED: Only convenio patients for consultation registration
  const patientType = "convenio";

  // Form state
  const [cpf, setCpf] = useState("");
  const [clientId, setClientId] = useState<number | null>(null);
  const [clientName, setClientName] = useState("");
  const [subscriptionStatus, setSubscriptionStatus] = useState("");
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [selectedDependentId, setSelectedDependentId] = useState<number | null>(
    null
  );
  const [foundDependent, setFoundDependent] = useState<Dependent | null>(null);
  const [categoryId, setCategoryId] = useState<string>("");
  const [serviceId, setServiceId] = useState<number | null>(null);
  const [locationId, setLocationId] = useState<string>("");
  const [value, setValue] = useState("");
  const [date, setDate] = useState("");
  const [time, setTime] = useState("");

  // UI state
  const [categories, setCategories] = useState<Category[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [filteredServices, setFilteredServices] = useState<Service[]>([]);
  const [attendanceLocations, setAttendanceLocations] = useState<
    AttendanceLocation[]
  >([]);
  const [hasSchedulingSubscription, setHasSchedulingSubscription] =
    useState(false);
  const [slotDuration, setSlotDuration] = useState<SlotDuration>(30);
  const [isLoading, setIsLoading] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Get API URL with fallback
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }

    return "http://localhost:3001";
  };

  // Load categories and services on component mount
  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        const apiUrl = getApiUrl();

        console.log("Fetching consultation data from:", apiUrl);

        // Fetch categories
        const categoriesResponse = await fetch(
          `${apiUrl}/api/service-categories`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!categoriesResponse.ok) {
          throw new Error("Falha ao carregar categorias");
        }

        const categoriesData = await categoriesResponse.json();
        setCategories(categoriesData);

        // Fetch services
        const servicesResponse = await fetch(`${apiUrl}/api/services`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!servicesResponse.ok) {
          throw new Error("Falha ao carregar serviços");
        }

        const servicesData = await servicesResponse.json();
        setServices(servicesData);

        // Fetch attendance locations
        const locationsResponse = await fetch(
          `${apiUrl}/api/attendance-locations`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (locationsResponse.ok) {
          const locationsData = await locationsResponse.json();
          setAttendanceLocations(locationsData);

          // Set default location if exists
          const defaultLocation = locationsData.find(
            (loc: AttendanceLocation) => loc.is_default
          );
          if (defaultLocation) {
            setLocationId(defaultLocation.id.toString());
          }
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        setError("Não foi possível carregar os dados necessários");
      }
    };

    fetchData();
  }, []);

  // Filter services when category changes
  useEffect(() => {
    if (categoryId) {
      const filtered = services.filter(
        (service) => service.category_id === Number.parseInt(categoryId)
      );
      setFilteredServices(filtered);
      setServiceId(null);
      setValue("");
    } else {
      setFilteredServices([]);
      setServiceId(null);
      setValue("");
    }
  }, [categoryId, services]);

  // Search client or dependent by CPF
  const searchByCpf = async () => {
    setError("");
    setSuccess("");

    // Validate CPF format
    if (!/^\d{11}$/.test(cpf.replace(/\D/g, ""))) {
      setError("CPF deve conter 11 dígitos numéricos");
      return;
    }

    try {
      setIsSearching(true);

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const cleanCpf = cpf.replace(/\D/g, "");

      // First, try to find a dependent with this CPF
      const dependentResponse = await fetch(
        `${apiUrl}/api/dependents/search?cpf=${cleanCpf}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (dependentResponse.ok) {
        const dependentData = await dependentResponse.json();

        // 🔥 Check if the dependent has active subscription
        if (dependentData.status !== "active") {
          setError(
            "Este dependente não pode ser atendido pois não possui assinatura ativa."
          );
          resetForm();
          return;
        }

        setFoundDependent(dependentData);
        setClientId(dependentData.client_id);
        setClientName(dependentData.client_name);
        setSubscriptionStatus(dependentData.status);
        setSelectedDependentId(dependentData.id);
        setDependents([]); // No dependents list needed when found directly
        setSuccess(
          `Dependente encontrado: ${dependentData.name} (Titular: ${
            dependentData.client_name
          }) - Status: ${
            dependentData.status === "active" ? "Ativo" : "Inativo"
          }`
        );
        return;
      }

      // If not found as dependent, try to find as client
      const clientResponse = await fetch(
        `${apiUrl}/api/clients/lookup?cpf=${cleanCpf}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!clientResponse.ok) {
        if (clientResponse.status === 404) {
          throw new Error(
            "Cliente ou dependente não encontrado. Verifique o CPF ou entre em contato com o administrador."
          );
        } else {
          throw new Error("Falha ao buscar cliente");
        }
      }

      const clientData = await clientResponse.json();

      // 🔥 Check if client has active subscription
      if (clientData.subscription_status !== "active") {
        setError(
          "Este cliente não pode ser atendido pois não possui assinatura ativa."
        );
        resetForm();
        return;
      }

      setClientId(clientData.id);
      setClientName(clientData.name);
      setSubscriptionStatus(clientData.subscription_status);
      setSelectedDependentId(null);
      setFoundDependent(null);

      // Fetch dependents
      const dependentsResponse = await fetch(
        `${apiUrl}/api/dependents?client_id=${clientData.id}&status=active`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (dependentsResponse.ok) {
        const dependentsData = await dependentsResponse.json();
        // Filter only active dependents
        setDependents(dependentsData);
      }

      setSuccess("Cliente encontrado com sucesso!");
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError("Ocorreu um erro ao buscar o cliente");
      }
      resetForm();
    } finally {
      setIsSearching(false);
    }
  };

  const resetForm = () => {
    setClientId(null);
    setClientName("");
    setSubscriptionStatus("");
    setDependents([]);
    setSelectedDependentId(null);
    setFoundDependent(null);
  };

  // Update value when service changes
  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selectedId = Number(e.target.value);
    setServiceId(selectedId);

    const selectedService = services.find(
      (service) => service.id === selectedId
    );
    if (selectedService) {
      setValue(selectedService.base_price.toString());
    }
  };

  // Format CPF as user types (###.###.###-##)
  const formatCpf = (value: string) => {
    // Remove non-numeric characters
    const numericValue = value.replace(/\D/g, "");

    // Limit to 11 digits
    const limitedValue = numericValue.slice(0, 11);

    setCpf(limitedValue);
  };

  const formattedCpf = cpf
    ? cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4")
    : "";

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    // Validate time format and slot
    const timeValidation = validateTimeSlot(time, slotDuration);
    if (!timeValidation.isValid) {
      setError(timeValidation.error || "Horário inválido");
      return;
    }

    // Validate form
    if (!clientId && !selectedDependentId && !foundDependent) {
      setError("É necessário selecionar um cliente ou dependente");
      return;
    }

    // 🔥 Double check subscription status before submitting
    if (subscriptionStatus !== "active") {
      setError(
        "Não é possível registrar consulta para cliente sem assinatura ativa"
      );
      return;
    }

    if (!serviceId) {
      setError("É necessário selecionar um serviço");
      return;
    }

    if (!value || Number(value) <= 0) {
      setError("O valor deve ser maior que zero");
      return;
    }

    if (!date || !time) {
      setError("Data e hora são obrigatórios");
      return;
    }

    const localDateTime = new Date(`${date}T${time}`);
    const utcDateTime = localDateTime.toISOString();

    try {
      setIsLoading(true);

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Prepare consultation data with proper patient identification
      const consultationData: any = {
        professional_id: user?.id,
        service_id: serviceId,
        location_id: locationId ? Number.parseInt(locationId) : null,
        value: Number(value),
        date: utcDateTime, // Send UTC ISO string instead of local datetime
        status: "scheduled",
        notes: null,
      };

      // Set patient based on what was found
      if (foundDependent) {
        // Direct dependent search result
        consultationData.dependent_id = foundDependent.id;
        console.log("🎯 Using found dependent:", foundDependent.id);
      } else if (selectedDependentId) {
        // Selected from dependents list
        consultationData.dependent_id = selectedDependentId;
        console.log("🎯 Using selected dependent:", selectedDependentId);
      } else if (clientId) {
        // Client (titular)
        consultationData.user_id = clientId;
        console.log("🎯 Using client:", clientId);
      }

      console.log("🔄 Final consultation data:", consultationData);
      // Create both consultation record and appointment
      const response = await fetch(`${apiUrl}/api/consultations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(consultationData),
      });

      console.log("📡 Consultation creation response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Consultation creation failed:", errorData);
        if (response.status === 409 && errorData.conflict) {
          setError(
            errorData.message ||
              "Este horário já está ocupado. Por favor, escolha outro horário."
          );
        } else {
          setError(errorData.message || "Falha ao registrar consulta");
        }
        return;
      }

      const responseData = await response.json();
      console.log("✅ Consultation and appointment created:", responseData);

      // Reset form
      setCpf("");
      setClientId(null);
      setClientName("");
      setSubscriptionStatus("");
      setSelectedDependentId(null);
      setFoundDependent(null);
      setDependents([]);
      setCategoryId("");
      setServiceId(null);
      setLocationId("");
      setValue("");
      setDate("");
      setTime("");

      setSuccess("Consulta registrada com sucesso!");

      // Redirect after a delay
      setTimeout(() => {
        navigate("/professional");
      }, 2000);
    } catch (error) {
      console.error("Error registering consultation:", error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError("Ocorreu um erro ao registrar a consulta");
      }
    } finally {
      setIsLoading(false);
    }
  };

  // 🔥 Function to get subscription status display
  const getSubscriptionStatusDisplay = (status: string) => {
    switch (status) {
      case "active":
        return {
          text: "Assinatura Ativa",
          className: "bg-green-100 text-green-800",
          icon: null,
        };
      case "pending":
        return {
          text: "Situação Cadastral Pendente",
          className: "bg-red-100 text-red-800",
          icon: <AlertTriangle className="h-4 w-4 mr-1" />,
        };
      case "expired":
        return {
          text: "Assinatura Vencida",
          className: "bg-red-100 text-red-800",
          icon: <AlertTriangle className="h-4 w-4 mr-1" />,
        };
      default:
        return {
          text: "Status Desconhecido",
          className: "bg-gray-100 text-gray-800",
          icon: <AlertTriangle className="h-4 w-4 mr-1" />,
        };
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          Registrar Nova Consulta
        </h1>
        <p className="text-gray-600">
          Preencha os dados para registrar uma nova consulta
        </p>
      </div>

      <div className="card">
        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded-md mb-4 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2 flex-shrink-0" />
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 text-green-600 p-3 rounded-md mb-4">
            {success}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Patient Selection for convenio only */}
          <div className="mb-6">
            <h2 className="text-lg font-semibold mb-3 flex items-center">
              <Search className="h-5 w-5 mr-2 text-red-600" />
              Buscar Cliente ou Dependente por CPF
            </h2>

            <div className="flex items-center space-x-2">
              <div className="flex-1">
                <input
                  type="text"
                  value={formattedCpf}
                  onChange={(e) => formatCpf(e.target.value)}
                  placeholder="000.000.000-00"
                  className="input"
                  disabled={isSearching || isLoading}
                />
              </div>

              <button
                type="button"
                onClick={searchByCpf}
                className={`btn btn-primary ${
                  isSearching ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isSearching || isLoading || !cpf}
              >
                {isSearching ? "Buscando..." : "Buscar"}
              </button>
            </div>

            {/* Display found client or dependent */}
            {clientId && (
              <div className="mt-3">
                <div
                  className={`p-3 rounded-md mb-3 ${
                    subscriptionStatus === "active"
                      ? "bg-green-50 text-green-700"
                      : "bg-red-50 text-red-700"
                  }`}
                >
                  {foundDependent ? (
                    <div className="flex items-center">
                      <User className="h-5 w-5 mr-2" />
                      <div className="flex-1">
                        <p>
                          <span className="font-medium">Dependente:</span>{" "}
                          {foundDependent.name}
                        </p>
                        <p>
                          <span className="font-medium">Titular:</span>{" "}
                          {clientName}
                        </p>
                        <div className="flex items-center mt-1">
                          <span className="font-medium mr-2">Status:</span>
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium flex items-center ${
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .className
                            }`}
                          >
                            {
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .icon
                            }
                            {
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .text
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center">
                      <Users className="h-5 w-5 mr-2" />
                      <div className="flex-1">
                        <p>
                          <span className="font-medium">Cliente:</span>{" "}
                          {clientName}
                        </p>
                        <div className="flex items-center mt-1">
                          <span className="font-medium mr-2">Status:</span>
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium flex items-center ${
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .className
                            }`}
                          >
                            {
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .icon
                            }
                            {
                              getSubscriptionStatusDisplay(subscriptionStatus)
                                .text
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                {/* Show dependents selection only if client was found directly and has active subscription */}
                {!foundDependent &&
                  dependents.length > 0 &&
                  subscriptionStatus === "active" && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Selecionar Dependente (opcional)
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
                            {dependent.name} (CPF:{" "}
                            {dependent.cpf.replace(
                              /(\d{3})(\d{3})(\d{3})(\d{2})/,
                              "$1.$2.$3-$4"
                            )}
                            )
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
              </div>
            )}
          </div>

          {/* Only show consultation details if subscription is active */}
          {subscriptionStatus === "active" && (
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center">
                <Calendar className="h-5 w-5 mr-2 text-red-600" />
                Detalhes da Consulta
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label
                    htmlFor="category"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Categoria do Serviço
                  </label>
                  <select
                    id="category"
                    value={categoryId}
                    onChange={(e) => setCategoryId(e.target.value)}
                    className="input"
                    disabled={isLoading}
                    required
                  >
                    <option value="">Selecione uma categoria</option>
                    {categories.map((category) => (
                      <option key={category.id} value={category.id}>
                        {category.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="service"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Serviço
                  </label>
                  <select
                    id="service"
                    value={serviceId || ""}
                    onChange={handleServiceChange}
                    className="input"
                    disabled={isLoading || !categoryId}
                    required
                  >
                    <option value="">Selecione um serviço</option>
                    {filteredServices.map((service) => (
                      <option key={service.id} value={service.id}>
                        {service.name} -{" "}
                        {new Intl.NumberFormat("pt-BR", {
                          style: "currency",
                          currency: "BRL",
                        }).format(service.base_price)}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="location"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Local de Atendimento
                  </label>
                  <select
                    id="location"
                    value={locationId}
                    onChange={(e) => setLocationId(e.target.value)}
                    className="input"
                    disabled={isLoading}
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
                  <label
                    htmlFor="value"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Valor (R$)
                  </label>
                  <input
                    id="value"
                    type="number"
                    min="0"
                    step="0.01"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    className="input"
                    disabled={isLoading}
                    required
                  />
                </div>

                <div>
                  <label
                    htmlFor="date"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Data
                  </label>
                  <input
                    id="date"
                    type="date"
                    value={date}
                    onChange={(e) => setDate(e.target.value)}
                    className="input"
                    disabled={isLoading}
                    required
                  />
                </div>

                <TimeInput
                  value={time}
                  onChange={setTime}
                  label="Horário"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => navigate("/professional")}
              className="btn btn-secondary mr-2"
              disabled={isLoading}
            >
              Cancelar
            </button>

            <button
              type="submit"
              className={`btn btn-primary ${
                isLoading || subscriptionStatus !== "active"
                  ? "opacity-70 cursor-not-allowed"
                  : ""
              }`}
              disabled={
                isLoading ||
                subscriptionStatus !== "active" ||
                (!clientId && !selectedDependentId) ||
                !serviceId ||
                !value ||
                !date ||
                !time
              }
            >
              {isLoading ? "Registrando..." : "Registrar Consulta"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default RegisterConsultationPage;
