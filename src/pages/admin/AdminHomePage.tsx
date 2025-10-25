import React, { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { Link } from "react-router-dom";
import {
  Users,
  FileText,
  BarChart2,
  CalendarClock,
  DollarSign,
} from "lucide-react";

type ConsultationCount = {
  total: number;
  today: number;
  week: number;
  month: number;
};

type UserCount = {
  clients: number;
  professionals: number;
  total: number;
};

type RevenueData = {
  total_revenue: number;
  revenue_by_professional: {
    professional_name: string;
    professional_percentage: number;
    revenue: number;
    consultation_count: number;
    professional_payment: number;
    clinic_revenue: number;
  }[];
  revenue_by_service: {
    service_name: string;
    revenue: number;
    consultation_count: number;
  }[];
};

const AdminHomePage: React.FC = () => {
  const { user } = useAuth();
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [consultationCounts, setConsultationCounts] =
    useState<ConsultationCount>({
      total: 0,
      today: 0,
      week: 0,
      month: 0,
    });
  const [userCounts, setUserCounts] = useState<UserCount>({
    clients: 0,
    professionals: 0,
    total: 0,
  });
  const [monthlyRevenue, setMonthlyRevenue] = useState<RevenueData | null>(
    null
  );

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

  // Get current month date range
  const getCurrentMonthRange = () => {
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    return {
      start: firstDay.toISOString().split("T")[0],
      end: lastDay.toISOString().split("T")[0],
    };
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);

        const token = localStorage.getItem("token");
        const apiUrl = getApiUrl();

        console.log("Fetching admin data from:", apiUrl);

        // Fetch all consultations
        const consultationsResponse = await fetch(
          `${apiUrl}/api/consultations`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!consultationsResponse.ok) {
          throw new Error("Falha ao carregar dados de consultas");
        }

        const consultationsData = await consultationsResponse.json();

        // Fetch all users
        const usersResponse = await fetch(`${apiUrl}/api/users`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (!usersResponse.ok) {
          throw new Error("Falha ao carregar dados de usuários");
          console.error(
            "Consultations response error:",
            consultationsResponse.status
          );
        }

        const usersData = await usersResponse.json();
        console.log("Users data loaded:", usersData.length);

        // Fetch monthly revenue report
        const dateRange = getCurrentMonthRange();
        const revenueResponse = await fetch(
          `${apiUrl}/api/reports/revenue?start_date=${dateRange.start}&end_date=${dateRange.end}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (revenueResponse.ok) {
          const revenueData = await revenueResponse.json();
          console.log("Revenue data loaded:", revenueData);
          setMonthlyRevenue(revenueData);
        } else {
          console.warn("Revenue data not available:", revenueResponse.status);
        }

        // Calculate consultation counts
        const now = new Date();
        const today = new Date(
          now.getFullYear(),
          now.getMonth(),
          now.getDate()
        );
        const weekAgo = new Date(now);
        weekAgo.setDate(now.getDate() - 7);
        const monthAgo = new Date(now);
        monthAgo.setMonth(now.getMonth() - 1);

        const todayCount = consultationsData.filter(
          (c: any) => new Date(c.date) >= today
        ).length;
        const weekCount = consultationsData.filter(
          (c: any) => new Date(c.date) >= weekAgo
        ).length;
        const monthCount = consultationsData.filter(
          (c: any) => new Date(c.date) >= monthAgo
        ).length;
        console.log("Consultations data loaded:", consultationsData.length);

        setConsultationCounts({
          total: consultationsData.length,
          today: todayCount,
          week: weekCount,
          month: monthCount,
        });

        // Calculate user counts correctly using roles array
        const clientCount = usersData.filter(
          (u: any) => u.roles && u.roles.includes("client")
        ).length;
        const professionalCount = usersData.filter(
          (u: any) => u.roles && u.roles.includes("professional")
        ).length;

        setUserCounts({
          clients: Number(clientCount) || 0,
          professionals: Number(professionalCount) || 0,
          total: Number(usersData.length) || 0,
        });

        // Fetch dependents data for additional stats
        try {
          const dependentsResponse = await fetch(
            `${apiUrl}/api/admin/dependents`,
            {
              headers: { Authorization: `Bearer ${token}` },
            }
          );

          if (dependentsResponse.ok) {
            const dependentsData = await dependentsResponse.json();
            console.log(
              "Dependents data loaded for stats:",
              dependentsData.length
            );

            // You could add dependent stats here if needed
          }
        } catch (error) {
          console.warn("Could not load dependents data:", error);
        }
      } catch (error) {
        console.error("Error fetching admin data:", error);
        setError("Não foi possível carregar os dados do painel");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  // Calculate total clinic revenue (what admin will receive)
  const calculateClinicRevenue = () => {
    if (!monthlyRevenue) return 0;
    if (
      !monthlyRevenue.revenue_by_professional ||
      !Array.isArray(monthlyRevenue.revenue_by_professional)
    )
      return 0;
    return monthlyRevenue.revenue_by_professional.reduce(
      (total, prof) => total + (Number(prof.clinic_revenue) || 0),
      0
    );
  };

  const statCards = [
    {
      title: "Total de Consultas",
      value: consultationCounts.total,
      icon: <CalendarClock className="h-8 w-8 text-red-600" />,
      link: "/admin/reports",
    },
    {
      title: "Clientes",
      value: userCounts.clients,
      icon: <Users className="h-8 w-8 text-red-600" />,
      link: "/admin/users",
    },
    {
      title: "Profissionais",
      value: userCounts.professionals,
      icon: <Users className="h-8 w-8 text-red-600" />,
      link: "/admin/users",
    },
    {
      title: "Contas a Receber",
      value: formatCurrency(calculateClinicRevenue()),
      icon: <DollarSign className="h-8 w-8 text-red-600" />,
      link: "/admin/reports",
      description: "Valor a receber dos profissionais este mês",
      isMonetary: true,
    },
  ];

  const quickLinks = [
    {
      title: "Gerenciar Usuários",
      description: "Adicionar, editar ou remover usuários do sistema",
      icon: <Users className="h-6 w-6 text-red-600" />,
      link: "/admin/users",
    },
    {
      title: "Gerenciar Serviços",
      description: "Configurar os serviços oferecidos e seus preços",
      icon: <FileText className="h-6 w-6 text-red-600" />,
      link: "/admin/services",
    },
    {
      title: "Ver Relatórios",
      description: "Acessar relatórios de faturamento e estatísticas",
      icon: <BarChart2 className="h-6 w-6 text-red-600" />,
      link: "/admin/reports",
    },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Olá, {user?.name}</h1>
        <p className="text-gray-600">Bem-vindo ao painel administrativo.</p>
      </div>

      {isLoading ? (
        <div className="text-center py-8">
          <p className="text-gray-600">Carregando dados...</p>
        </div>
      ) : error ? (
        <div className="bg-red-50 text-red-600 p-4 rounded-md mb-6">
          {error}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {statCards.map((card, index) => (
              <Link
                key={index}
                to={card.link}
                className="card bg-white hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-center">
                  <div className="mr-4">{card.icon}</div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-700">
                      {card.title}
                    </h3>
                    <p
                      className={`text-3xl font-bold text-gray-900 ${
                        card.isMonetary ? "text-green-600" : ""
                      }`}
                    >
                      {card.value}
                    </p>
                    {card.description && (
                      <p className="text-sm text-gray-600">
                        {card.description}
                      </p>
                    )}
                  </div>
                </div>
              </Link>
            ))}
          </div>

          {monthlyRevenue && (
            <div className="card mb-8">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <DollarSign className="h-5 w-5 text-green-600 mr-2" />
                Resumo Financeiro do Mês
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <p className="text-sm text-blue-600 font-medium">
                    Faturamento Total
                  </p>
                  <p className="text-2xl font-bold text-blue-700">
                    {formatCurrency(monthlyRevenue.total_revenue)}
                  </p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <p className="text-sm text-green-600 font-medium">
                    Receita do Convênio
                  </p>
                  <p className="text-2xl font-bold text-green-700">
                    {formatCurrency(Number(calculateClinicRevenue()) || 0)}
                  </p>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg">
                  <p className="text-sm text-orange-600 font-medium">
                    Faturamento dos Profissionais
                  </p>
                  <p className="text-2xl font-bold text-orange-700">
                    {formatCurrency(
                      monthlyRevenue.revenue_by_professional?.reduce(
                        (total, prof) =>
                          total + (Number(prof.professional_payment) || 0),
                        0
                      ) || 0
                    )}
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {quickLinks.map((link, index) => (
              <Link
                key={index}
                to={link.link}
                className="card hover:shadow-lg transition-shadow flex flex-col items-center text-center p-6"
              >
                <div className="bg-red-50 p-4 rounded-full mb-4">
                  {link.icon}
                </div>
                <h3 className="text-lg font-semibold mb-2">{link.title}</h3>
                <p className="text-gray-600">{link.description}</p>
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

export default AdminHomePage;
