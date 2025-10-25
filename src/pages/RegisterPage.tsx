import React, { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Link } from "react-router-dom";
import { UserPlus, ArrowLeft, Eye, EyeOff, FileText, X, Check } from "lucide-react";

const RegisterPage: React.FC = () => {
  // Form state
  const [formData, setFormData] = useState({
    name: "",
    cpf: "",
    email: "",
    phone: "",
    birth_date: "",
    address: "",
    address_number: "",
    address_complement: "",
    neighborhood: "",
    city: "",
    state: "",
    password: "",
    confirmPassword: "",
  });

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  
  // Terms of service state
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  
  const { selectRole } = useAuth();

  // Get API URL - PRODUCTION READY
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }

    return "http://localhost:3001";
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setFormData((prev) => ({ ...prev, cpf: limitedValue }));
  };

  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    let formattedValue = limitedValue;

    if (limitedValue.length > 2) {
      formattedValue = `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(2)}`;
      if (limitedValue.length > 7) {
        formattedValue = `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(
          2,
          7
        )}-${limitedValue.slice(7)}`;
      }
    }

    setFormData((prev) => ({ ...prev, phone: formattedValue }));
  };

  const formattedCpf = formData.cpf
    ? formData.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4")
    : "";

  const validateForm = () => {
    // Required fields
    if (!formData.name.trim()) {
      setError("Nome é obrigatório");
      return false;
    }

    if (!formData.cpf) {
      setError("CPF é obrigatório");
      return false;
    }

    if (!/^\d{11}$/.test(formData.cpf)) {
      setError("CPF deve conter 11 dígitos numéricos");
      return false;
    }

    if (!formData.password) {
      setError("Senha é obrigatória");
      return false;
    }

    if (formData.password.length < 6) {
      setError("Senha deve ter pelo menos 6 caracteres");
      return false;
    }

    if (formData.password !== formData.confirmPassword) {
      setError("Senhas não coincidem");
      return false;
    }

    // Email validation (if provided)
    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setError("Email inválido");
      return false;
    }

    // Terms acceptance validation
    if (!acceptedTerms) {
      setError("Você deve aceitar o termo de adesão para prosseguir");
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!validateForm()) {
      return;
    }

    try {
      setIsLoading(true);

      const apiUrl = getApiUrl();
      const registerUrl = `${apiUrl}/api/auth/register`;

      console.log("Making registration request to:", registerUrl);

      const response = await fetch(registerUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: formData.name.trim(),
          cpf: formData.cpf,
          email: formData.email.trim() || null,
          phone: formData.phone.replace(/\D/g, "") || null,
          birth_date: formData.birth_date || null,
          address: formData.address.trim() || null,
          address_number: formData.address_number.trim() || null,
          address_complement: formData.address_complement.trim() || null,
          neighborhood: formData.neighborhood.trim() || null,
          city: formData.city.trim() || null,
          state: formData.state || null,
          password: formData.password,
        }),
        credentials: "include",
      });

      console.log("Registration response status:", response.status);

      if (!response.ok) {
        let errorMessage = "Erro ao criar conta";
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorMessage;
        } catch (e) {
          console.error("Error parsing error response:", e);
        }
        throw new Error(errorMessage);
      }

      const data = await response.json();
      console.log("Registration successful:", data);

      // Auto-select client role since registration is only for clients
      await selectRole(data.user.id, "client");
    } catch (error) {
      console.error("Registration error:", error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError("Ocorreu um erro ao criar a conta");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const openTermsModal = () => {
    setShowTermsModal(true);
  };

  const closeTermsModal = () => {
    setShowTermsModal(false);
  };

  const acceptTermsFromModal = () => {
    setAcceptedTerms(true);
    setShowTermsModal(false);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full">
        <div className="bg-white rounded-xl shadow-lg p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <img
              src="/logo_quiroferreira.svg"
              alt="Logo Quiro Ferreira"
              className="w-32 mx-auto mb-6"
            />
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Criar Conta de Cliente
            </h1>
            <p className="text-gray-600">
              Preencha seus dados para se cadastrar no convênio
            </p>
          </div>

          {/* Back to login link */}
          <div className="mb-6">
            <Link
              to="/"
              className="inline-flex items-center text-red-600 hover:text-red-700 transition-colors"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Voltar para o login
            </Link>
          </div>

          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Personal Information */}
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <UserPlus className="h-5 w-5 mr-2 text-red-600" />
                Informações Pessoais
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome Completo *
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Digite seu nome completo"
                    disabled={isLoading}
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CPF *
                  </label>
                  <input
                    type="text"
                    value={formattedCpf}
                    onChange={(e) => formatCpf(e.target.value)}
                    className="input"
                    placeholder="000.000.000-00"
                    disabled={isLoading}
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="seu@email.com"
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Telefone
                  </label>
                  <input
                    type="text"
                    value={formData.phone}
                    onChange={(e) => formatPhone(e.target.value)}
                    className="input"
                    placeholder="(00) 00000-0000"
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data de Nascimento
                  </label>
                  <input
                    type="date"
                    name="birth_date"
                    value={formData.birth_date}
                    onChange={handleInputChange}
                    className="input"
                    disabled={isLoading}
                  />
                </div>
              </div>
            </div>

            {/* Address Information */}
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Endereço
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Endereço
                  </label>
                  <input
                    type="text"
                    name="address"
                    value={formData.address}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Rua, Avenida, etc."
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Número
                  </label>
                  <input
                    type="text"
                    name="address_number"
                    value={formData.address_number}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="123"
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Complemento
                  </label>
                  <input
                    type="text"
                    name="address_complement"
                    value={formData.address_complement}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Apto, Bloco, etc."
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Bairro
                  </label>
                  <input
                    type="text"
                    name="neighborhood"
                    value={formData.neighborhood}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Nome do bairro"
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Cidade
                  </label>
                  <input
                    type="text"
                    name="city"
                    value={formData.city}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Nome da cidade"
                    disabled={isLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Estado
                  </label>
                  <select
                    name="state"
                    value={formData.state}
                    onChange={handleInputChange}
                    className="input"
                    disabled={isLoading}
                  >
                    <option value="">Selecione...</option>
                    <option value="AC">Acre</option>
                    <option value="AL">Alagoas</option>
                    <option value="AP">Amapá</option>
                    <option value="AM">Amazonas</option>
                    <option value="BA">Bahia</option>
                    <option value="CE">Ceará</option>
                    <option value="DF">Distrito Federal</option>
                    <option value="ES">Espírito Santo</option>
                    <option value="GO">Goiás</option>
                    <option value="MA">Maranhão</option>
                    <option value="MT">Mato Grosso</option>
                    <option value="MS">Mato Grosso do Sul</option>
                    <option value="MG">Minas Gerais</option>
                    <option value="PA">Pará</option>
                    <option value="PB">Paraíba</option>
                    <option value="PR">Paraná</option>
                    <option value="PE">Pernambuco</option>
                    <option value="PI">Piauí</option>
                    <option value="RJ">Rio de Janeiro</option>
                    <option value="RN">Rio Grande do Norte</option>
                    <option value="RS">Rio Grande do Sul</option>
                    <option value="RO">Rondônia</option>
                    <option value="RR">Roraima</option>
                    <option value="SC">Santa Catarina</option>
                    <option value="SP">São Paulo</option>
                    <option value="SE">Sergipe</option>
                    <option value="TO">Tocantins</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Security Information */}
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Segurança
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Senha *
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      name="password"
                      value={formData.password}
                      onChange={handleInputChange}
                      className="input pr-10"
                      placeholder="Mínimo 6 caracteres"
                      disabled={isLoading}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5" />
                      ) : (
                        <Eye className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Confirmar Senha *
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? "text" : "password"}
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      className="input pr-10"
                      placeholder="Digite a senha novamente"
                      disabled={isLoading}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                    >
                      {showConfirmPassword ? (
                        <EyeOff className="h-5 w-5" />
                      ) : (
                        <Eye className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Terms of Service */}
            <div className="border-t border-gray-200 pt-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <FileText className="h-5 w-5 mr-2 text-red-600" />
                Termo de Adesão
              </h3>

              <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
                <div className="flex items-start">
                  <FileText className="h-5 w-5 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-sm text-red-800 mb-3">
                      <strong>Leitura obrigatória:</strong> Antes de prosseguir, você deve ler e aceitar o Termo de Adesão ao Cartão Quiro Ferreira Saúde.
                    </p>
                    <button
                      type="button"
                      onClick={openTermsModal}
                      className="inline-flex items-center text-red-600 hover:text-red-700 font-medium transition-colors"
                      disabled={isLoading}
                    >
                      <FileText className="h-4 w-4 mr-2" />
                      Leia aqui o Termo de Adesão
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-start">
                <input
                  type="checkbox"
                  id="acceptTerms"
                  checked={acceptedTerms}
                  onChange={(e) => setAcceptedTerms(e.target.checked)}
                  className="mt-1 h-4 w-4 text-red-600 border-gray-300 rounded focus:ring-red-500 focus:ring-2"
                  disabled={isLoading}
                  required
                />
                <label htmlFor="acceptTerms" className="ml-3 text-sm text-gray-700">
                  <span className="font-medium">Li e concordo com o Termo de Adesão</span> ao Cartão Quiro Ferreira Saúde. 
                  Declaro que entendi que este não é um plano de saúde, mas sim um cartão de convênio de descontos. *
                </label>
              </div>
            </div>

            {/* Submit Button */}
            <div className="pt-6">
              <button
                type="submit"
                className={`w-full btn btn-primary ${
                  isLoading || !acceptedTerms ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isLoading || !acceptedTerms}
              >
                {isLoading ? "Criando conta..." : "Criar Conta"}
              </button>
            </div>

            {/* Login link */}
            <div className="text-center">
              <p className="text-sm text-gray-600">
                Já possui uma conta?{" "}
                <Link
                  to="/"
                  className="text-red-600 hover:text-red-700 font-medium"
                >
                  Fazer login
                </Link>
              </p>
            </div>
          </form>
        </div>
      </div>

      {/* Terms of Service Modal */}
      {showTermsModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h2 className="text-2xl font-bold text-gray-900 flex items-center">
                <FileText className="h-6 w-6 text-red-600 mr-3" />
                Termo de Adesão ao Cartão Quiro Ferreira Saúde
              </h2>
              <button
                onClick={closeTermsModal}
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
              <div className="prose prose-sm max-w-none">
                <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
                  <p className="text-yellow-800 font-medium">
                    <strong>(Leitura obrigatória antes de confirmar a adesão)</strong>
                  </p>
                  <p className="text-yellow-700 mt-2">
                    Ao prosseguir, você declara que leu, entendeu e está de acordo com os termos abaixo:
                  </p>
                </div>

                <div className="space-y-6">
                  <section>
                    <h3 className="text-lg font-bold text-gray-900 mb-3">1. NATUREZA DO CARTÃO</h3>
                    <div className="space-y-3 text-gray-700">
                      <p>
                        O <strong>Cartão Quiro Ferreira Saúde não é um plano de saúde</strong>, não oferece cobertura hospitalar, 
                        reembolso ou garantia de atendimento médico emergencial.
                      </p>
                      <p>
                        Trata-se de um <strong>cartão de convênio de descontos</strong>, que proporciona benefícios em forma de 
                        abatimento nos valores de serviços de saúde e bem-estar oferecidos por parceiros da Quiro Ferreira Saúde.
                      </p>
                      <p>
                        Ao aderir a este termo, o usuário reconhece que está contratando um <strong>serviço de descontos</strong>, 
                        e não um plano regulamentado pela ANS (Agência Nacional de Saúde Suplementar).
                      </p>
                    </div>
                  </section>

                  <section>
                    <h3 className="text-lg font-bold text-gray-900 mb-3">2. RESPONSABILIDADE PELOS SERVIÇOS</h3>
                    <div className="space-y-3 text-gray-700">
                      <p>
                        Os serviços prestados por terceiros (clínicas, médicos, dentistas, farmácias, entre outros) são de 
                        <strong> total responsabilidade dos profissionais ou empresas parceiras</strong>.
                      </p>
                      <p>
                        A Quiro Ferreira Saúde atua apenas como <strong>facilitadora</strong>, conectando o conveniado aos 
                        parceiros e negociando os descontos, sem se responsabilizar por falhas, danos ou problemas que 
                        possam ocorrer nos atendimentos.
                      </p>
                      <p>
                        Qualquer demanda, reclamação ou disputa referente à prestação dos serviços deve ser resolvida 
                        <strong> diretamente com o profissional ou empresa responsável</strong>.
                      </p>
                    </div>
                  </section>

                  <section>
                    <h3 className="text-lg font-bold text-gray-900 mb-3">3. DESCONTOS E LIMITAÇÕES</h3>
                    <div className="space-y-3 text-gray-700">
                      <p>
                        O <strong>desconto de 50% é exclusivo para atendimentos realizados na clínica Quiro Ferreira</strong>.
                      </p>
                      <p>
                        Os demais parceiros do Cartão Quiro Ferreira Saúde oferecem <strong>descontos variados</strong>, 
                        definidos individualmente por cada prestador.
                      </p>
                      <p>
                        Os percentuais de desconto podem variar de acordo com os serviços oferecidos e a localização dos parceiros.
                      </p>
                    </div>
                  </section>

                  <section>
                    <h3 className="text-lg font-bold text-gray-900 mb-3">4. ACEITE DIGITAL</h3>
                    <div className="space-y-3 text-gray-700">
                      <p>
                        Ao clicar em <strong>"Li e concordo com os termos"</strong>, o usuário declara estar plenamente 
                        ciente e de acordo com todas as cláusulas deste termo.
                      </p>
                      <p>
                        Este aceite tem <strong>validade jurídica como um contrato digital</strong>, conforme a legislação 
                        brasileira (Lei nº 13.709/18 - LGPD e Código Civil).
                      </p>
                    </div>
                  </section>
                </div>

                <div className="bg-red-50 border border-red-200 rounded-lg p-4 mt-6">
                  <p className="text-red-800 font-medium text-center">
                    <strong>IMPORTANTE:</strong> Este documento deve ser lido na íntegra antes de prosseguir com a adesão.
                  </p>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200 bg-gray-50">
              <button
                onClick={closeTermsModal}
                className="btn btn-secondary"
              >
                Fechar
              </button>
              <button
                onClick={acceptTermsFromModal}
                className="btn btn-primary flex items-center"
              >
                <Check className="h-5 w-5 mr-2" />
                Li e Concordo com os Termos
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RegisterPage;