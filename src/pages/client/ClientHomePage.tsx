import React, { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { CalendarClock, AlertCircle, Filter, User, Users } from "lucide-react";
import DependentsSection from "./DependentsSection";
import PaymentSection from "./PaymentSection";

type Consultation = {
  id: number;
  date: string;
  value: number;
  service_name: string;
  professional_name: string;
  client_name: string;
  is_dependent: boolean;
};

type Dependent = {
  id: number;
  name: string;
  cpf: string;
};

const ClientHomePage: React.FC = () => {
  const { user } = useAuth();
  const [consultations, setConsultations] = useState<Consultation[]>([]);
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [filteredConsultations, setFilteredConsultations] = useState<Consultation[]>([]);
  const [selectedFilter, setSelectedFilter] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [subscriptionStatus, setSubscriptionStatus] = useState<string>("");
  const [subscriptionExpiry, setSubscriptionExpiry] = useState<string | null>(
    null
  );

  // Get API URL with fallback
  const getApiUrl = () => {
    if (import.meta.env.VITE_API_URL) {
      return import.meta.env.VITE_API_URL;
    }

    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://convenioquiroferreira.onrender.com";
    }

    return "http://localhost:3001";
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);

        const token = localStorage.getItem("token");
        const apiUrl = getApiUrl();

        console.log("Fetching client data from:", apiUrl);

        // Fetch consultations
        const consultationsResponse = await fetch(`${apiUrl}/api/consultations`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!consultationsResponse.ok) {
          throw new Error("Falha ao carregar consultas");
        }

        const consultationsData = await consultationsResponse.json();
        setConsultations(consultationsData);

        // Fetch dependents
        const dependentsResponse = await fetch(`${apiUrl}/api/dependents/${user?.id}`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (dependentsResponse.ok) {
          const dependentsData = await dependentsResponse.json();
          setDependents(dependentsData);
        }

        // Fetch subscription status
        const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (userResponse.ok) {
          const userData = await userResponse.json();
          setSubscriptionStatus(userData.subscription_status || "pending");
          setSubscriptionExpiry(userData.subscription_expiry);
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        setError("Não foi possível carregar seu histórico de consultas");
      } finally {
        setIsLoading(false);
      }
    };

    if (user?.id) {
      fetchData();
    }
  }, [user?.id]);

  // Filter consultations based on selected filter
  useEffect(() => {
    if (selectedFilter === 'all') {
      setFilteredConsultations(consultations);
    } else if (selectedFilter === 'titular') {
      // Show only consultations for the titular (client_name matches user name)
      setFilteredConsultations(consultations.filter(c => c.client_name === user?.name));
    } else {
      // Show consultations for specific dependent
      const dependent = dependents.find(d => d.id.toString() === selectedFilter);
      if (dependent) {
        setFilteredConsultations(consultations.filter(c => c.client_name === dependent.name));
      }
    }
  }, [consultations, selectedFilter, dependents, user?.name]);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return format(date, "dd 'de' MMMM 'de' yyyy 'às' HH:mm", { locale: ptBR });
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  const getFilterOptions = () => {
    const options = [
      { value: 'all', label: 'Todas as consultas', icon: <CalendarClock className="h-4 w-4" /> },
      { value: 'titular', label: `${user?.name} (Titular)`, icon: <User className="h-4 w-4" /> }
    ];

    dependents.forEach(dependent => {
      options.push({
        value: dependent.id.toString(),
        label: dependent.name,
        icon: <Users className="h-4 w-4" />
      });
    });

    return options;
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Olá, {user?.name}</h1>
        <p className="text-gray-600">Bem-vindo ao seu painel de cliente.</p>
      </div>

      {subscriptionStatus === "expired" && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <p className="text-red-700">
              Sua assinatura está vencida. Por favor, renove para continuar
              utilizando os serviços.
            </p>
          </div>
        </div>
      )}

      {subscriptionStatus === "pending" && (
        <div className="bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-yellow-600 mr-2" />
            <p className="text-yellow-700">
              Complete seu cadastro realizando o pagamento da assinatura.
            </p>
          </div>
        </div>
      )}

      {user && (
        <PaymentSection
          userId={user.id}
          subscriptionStatus={subscriptionStatus}
          subscriptionExpiry={subscriptionExpiry}
        />
      )}

      {user && <DependentsSection clientId={user.id} />}

      <div className="card mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <CalendarClock className="h-6 w-6 text-red-600 mr-2" />
            <h2 className="text-xl font-semibold">Histórico de Consultas</h2>
          </div>

          {/* Filter dropdown */}
          {(consultations.length > 0 || dependents.length > 0) && (
            <div className="flex items-center space-x-2">
              <Filter className="h-5 w-5 text-gray-500" />
              <select
                value={selectedFilter}
                onChange={(e) => setSelectedFilter(e.target.value)}
                className="input w-auto min-w-[200px]"
              >
                {getFilterOptions().map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="text-center py-8">
            <p className="text-gray-600">Carregando consultas...</p>
          </div>
        ) : error ? (
          <div className="bg-red-50 text-red-600 p-4 rounded-md">{error}</div>
        ) : filteredConsultations.length === 0 ? (
          <div className="text-center py-8 bg-gray-50 rounded-lg">
            <CalendarClock className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {selectedFilter === 'all' 
                ? 'Nenhuma consulta encontrada'
                : `Nenhuma consulta encontrada para ${
                    selectedFilter === 'titular' 
                      ? 'o titular' 
                      : dependents.find(d => d.id.toString() === selectedFilter)?.name || 'este usuário'
                  }`
              }
            </h3>
            <p className="text-gray-600">
              {selectedFilter === 'all' 
                ? 'Você ainda não possui consultas registradas.'
                : 'Não há consultas registradas para este usuário.'
              }
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Data</th>
                  <th>Paciente</th>
                  <th>Serviço</th>
                  <th>Profissional</th>
                  <th>Valor</th>
                </tr>
              </thead>
              <tbody>
                {filteredConsultations.map((consultation) => (
                  <tr key={consultation.id}>
                    <td>{formatDate(consultation.date)}</td>
                    <td>
                      <div className="flex items-center">
                        {consultation.client_name === user?.name ? (
                          <User className="h-4 w-4 text-green-600 mr-2" />
                        ) : (
                          <Users className="h-4 w-4 text-blue-600 mr-2" />
                        )}
                        {consultation.client_name}
                        {consultation.client_name === user?.name && (
                          <span className="ml-2 px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs">
                            Titular
                          </span>
                        )}
                      </div>
                    </td>
                    <td>{consultation.service_name}</td>
                    <td>{consultation.professional_name}</td>
                    <td>{formatCurrency(consultation.value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Summary */}
        {filteredConsultations.length > 0 && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">
                {filteredConsultations.length} consulta(s) encontrada(s)
                {selectedFilter !== 'all' && (
                  <span className="ml-1">
                    para {selectedFilter === 'titular' 
                      ? 'o titular' 
                      : dependents.find(d => d.id.toString() === selectedFilter)?.name
                    }
                  </span>
                )}
              </span>
              <span className="text-sm font-medium text-gray-900">
                Total: {formatCurrency(
                  filteredConsultations.reduce((sum, c) => sum + c.value, 0)
                )}
              </span>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="text-xl font-semibold mb-4">Informações do Convênio</h2>
        <div className="space-y-2">
          <p>
            <span className="font-medium">Telefone para contato:</span> (64)
            98124-9199
          </p>
          <p>
            <span className="font-medium">Horário de atendimento:</span> Segunda
            a Sexta, das 8h às 18h
          </p>
        </div>
      </div>
    </div>
  );
};

export default ClientHomePage;