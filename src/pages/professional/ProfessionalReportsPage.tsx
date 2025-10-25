import type React from "react";
import { useState, useEffect } from "react";
import { BarChart2, Calendar, TrendingUp, Users, FileText } from "lucide-react";

type DetailedReport = {
  summary: {
    total_consultations: number;
    convenio_consultations: number;
    private_consultations: number;
    total_revenue: number;
    convenio_revenue: number;
    private_revenue: number;
    professional_percentage: number;
    amount_to_pay: number;
  };
};

const ProfessionalReportsPage: React.FC = () => {
  const [startDate, setStartDate] = useState(getDefaultStartDate());
  const [endDate, setEndDate] = useState(getDefaultEndDate());
  const [report, setReport] = useState<DetailedReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

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

  // Get default date range (current month)
  function getDefaultStartDate() {
    const date = new Date();
    date.setDate(1); // First day of current month
    return date.toISOString().split("T")[0];
  }

  function getDefaultEndDate() {
    const date = new Date();
    return date.toISOString().split("T")[0];
  }

  useEffect(() => {
    fetchReport();
  }, []);

  const fetchReport = async () => {
    try {
      setIsLoading(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Fetching detailed report with dates:", {
        startDate,
        endDate,
      });
      console.log(
        "🔄 Frontend dates being sent:",
        `start_date=${startDate}&end_date=${endDate}`
      );

      const response = await fetch(
        `${apiUrl}/api/reports/professional-detailed?start_date=${startDate}&end_date=${endDate}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      console.log("📡 Detailed report response status:", response.status);
      console.log(
        "📡 Response content-type:",
        response.headers.get("content-type")
      );

      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const textResponse = await response.text();
        console.error(
          "❌ Response is not JSON:",
          textResponse.substring(0, 200)
        );
        throw new Error(
          "A rota da API não foi encontrada. Verifique se o endpoint '/api/reports/professional-detailed' está configurado corretamente no servidor."
        );
      }

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Detailed report error:", errorData);
        throw new Error(errorData.message || "Falha ao carregar relatório");
      }

      const data = await response.json();
      console.log("✅ Detailed report data received:", data);
      setReport(data);
    } catch (error) {
      console.error("Error fetching report:", error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError(
          "Não foi possível carregar o relatório. Verifique sua conexão e tente novamente."
        );
      }
      setReport(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchReport();
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR");
  };

  // Format date for display (convert from UTC to Brazil local time)
  const formatDateTimeFromUTC = (utcDateString: string) => {
    const date = new Date(utcDateString);
    return date.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          Relatórios Profissionais
        </h1>
        <p className="text-gray-600">
          Visualize dados detalhados de suas consultas e faturamento
        </p>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center mb-4">
          <Calendar className="h-6 w-6 text-red-600 mr-2" />
          <h2 className="text-xl font-semibold">Selecione o Período</h2>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label
                htmlFor="startDate"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Data Inicial
              </label>
              <input
                id="startDate"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="input"
                required
              />
            </div>

            <div>
              <label
                htmlFor="endDate"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Data Final
              </label>
              <input
                id="endDate"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="input"
                required
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                className={`btn btn-primary w-full ${
                  isLoading ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isLoading}
              >
                {isLoading ? "Carregando..." : "Gerar Relatório"}
              </button>
            </div>
          </div>
        </form>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Total de Consultas
                </h3>
                <Users className="h-5 w-5 text-blue-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {report.summary.total_consultations}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Todas as consultas realizadas
              </p>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Consultas Convênio
                </h3>
                <FileText className="h-5 w-5 text-green-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {report.summary.convenio_consultations}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Atendimentos pelo convênio
              </p>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Consultas Particulares
                </h3>
                <Users className="h-5 w-5 text-purple-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {report.summary.private_consultations}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Atendimentos particulares
              </p>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Faturamento Total
                </h3>
                <TrendingUp className="h-5 w-5 text-green-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(report.summary.total_revenue)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Receita bruta do período
              </p>
            </div>
          </div>

          {/* Revenue Breakdown */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-center mb-6">
              <BarChart2 className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Detalhamento Financeiro</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="p-4 bg-blue-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Receita do Convênio</p>
                  <p className="text-2xl font-bold text-blue-600">
                    {formatCurrency(report.summary.convenio_revenue)}
                  </p>
                  <p className="text-sm text-gray-500">
                    Atendimentos pelo convênio
                  </p>
                </div>
              </div>

              <div className="p-4 bg-purple-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Receita Particular</p>
                  <p className="text-2xl font-bold text-purple-600">
                    {formatCurrency(report.summary.private_revenue)}
                  </p>
                  <p className="text-sm text-gray-500">
                    100% para o profissional
                  </p>
                </div>
              </div>

              <div className="p-4 bg-green-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Sua Porcentagem</p>
                  <p className="text-2xl font-bold text-green-600">
                    {report.summary.professional_percentage}%
                  </p>
                  <p className="text-sm text-gray-500">
                    Do faturamento do convênio
                  </p>
                </div>
              </div>

              <div className="p-4 bg-red-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Valor a Pagar</p>
                  <p className="text-2xl font-bold text-red-600">
                    {formatCurrency(report.summary.amount_to_pay)}
                  </p>
                  <p className="text-sm text-gray-500">Para o convênio</p>
                </div>
              </div>
            </div>

            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <h3 className="font-semibold text-gray-900 mb-3">
                Resumo do Período
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <p>
                    <strong>Período:</strong>{" "}
                    {startDate
                      ? new Date(startDate + "T12:00:00").toLocaleDateString(
                          "pt-BR"
                        )
                      : ""}{" "}
                    a{" "}
                    {endDate
                      ? new Date(endDate + "T12:00:00").toLocaleDateString(
                          "pt-BR"
                        )
                      : ""}
                  </p>
                  <p>
                    <strong>Total de Consultas:</strong>{" "}
                    {report.summary.total_consultations}
                  </p>
                  <p>
                    <strong>Faturamento Bruto:</strong>{" "}
                    {formatCurrency(report.summary.total_revenue)}
                  </p>
                </div>
                <div>
                  <p>
                    <strong>Receita Líquida:</strong>{" "}
                    {formatCurrency(
                      report.summary.private_revenue +
                        report.summary.convenio_revenue *
                          (report.summary.professional_percentage / 100)
                    )}
                  </p>
                  <p>
                    <strong>Repasse ao Convênio:</strong>{" "}
                    {formatCurrency(report.summary.amount_to_pay)}
                  </p>
                  <p>
                    <strong>Porcentagem do Convênio:</strong>{" "}
                    {100 - report.summary.professional_percentage}%
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Charts placeholder */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <h3 className="text-lg font-semibold mb-4">
              Distribuição de Consultas
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="text-center">
                <div className="w-32 h-32 mx-auto mb-4 relative">
                  <div className="w-full h-full rounded-full border-8 border-green-200 border-t-green-600 flex items-center justify-center">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">
                        {report.summary.convenio_consultations}
                      </div>
                      <div className="text-xs text-gray-500">Convênio</div>
                    </div>
                  </div>
                </div>
                <p className="text-sm text-gray-600">
                  {report.summary.total_consultations > 0
                    ? Math.round(
                        (report.summary.convenio_consultations /
                          report.summary.total_consultations) *
                          100
                      )
                    : 0}
                  % do total
                </p>
              </div>

              <div className="text-center">
                <div className="w-32 h-32 mx-auto mb-4 relative">
                  <div className="w-full h-full rounded-full border-8 border-purple-200 border-t-purple-600 flex items-center justify-center">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-600">
                        {report.summary.private_consultations}
                      </div>
                      <div className="text-xs text-gray-500">Particular</div>
                    </div>
                  </div>
                </div>
                <p className="text-sm text-gray-600">
                  {report.summary.total_consultations > 0
                    ? Math.round(
                        (report.summary.private_consultations /
                          report.summary.total_consultations) *
                          100
                      )
                    : 0}
                  % do total
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProfessionalReportsPage;
