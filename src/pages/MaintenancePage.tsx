import React from 'react';
import { Wrench, Clock, Phone, Mail, AlertTriangle } from 'lucide-react';

const MaintenancePage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full">
        {/* Main Card */}
        <div className="bg-white rounded-2xl shadow-2xl overflow-hidden">
          {/* Header with gradient */}
          <div className="bg-gradient-to-r from-red-600 to-red-700 p-8 text-center">
            <div className="w-20 h-20 bg-white bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
              <Wrench className="h-10 w-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Sistema em Manutenção
            </h1>
            <p className="text-red-100 text-lg">
              Estamos trabalhando para melhorar sua experiência
            </p>
          </div>

          {/* Content */}
          <div className="p-8">
            <div className="text-center mb-8">
              <div className="flex items-center justify-center mb-4">
                <Clock className="h-6 w-6 text-red-600 mr-2" />
                <span className="text-lg font-semibold text-gray-900">
                  Manutenção Programada
                </span>
              </div>
              
              <p className="text-gray-600 text-lg leading-relaxed mb-6">
                Nosso sistema está temporariamente indisponível para manutenção e melhorias. 
                Estamos trabalhando para voltar o mais rápido possível.
              </p>

              <div className="bg-blue-50 border border-blue-200 rounded-xl p-6 mb-6">
                <div className="flex items-start">
                  <AlertTriangle className="h-6 w-6 text-blue-600 mr-3 mt-1 flex-shrink-0" />
                  <div className="text-left">
                    <h3 className="font-semibold text-blue-900 mb-2">
                      O que estamos fazendo:
                    </h3>
                    <ul className="text-blue-700 space-y-1 text-sm">
                      <li>• Atualizações de segurança</li>
                      <li>• Melhorias de performance</li>
                      <li>• Correções e otimizações</li>
                      <li>• Implementação de novas funcionalidades</li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 mb-8">
                <p className="text-yellow-800 font-medium">
                  ⏰ Previsão de retorno: Em breve
                </p>
                <p className="text-yellow-700 text-sm mt-1">
                  Acompanhe nossas redes sociais para atualizações em tempo real
                </p>
              </div>
            </div>

            {/* Contact Information */}
            <div className="border-t border-gray-200 pt-8">
              <h3 className="text-xl font-semibold text-gray-900 mb-6 text-center">
                Precisa de Ajuda?
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-gray-50 rounded-xl p-6 text-center">
                  <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Phone className="h-6 w-6 text-red-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Telefone</h4>
                  <p className="text-gray-600 mb-3">
                    Entre em contato conosco
                  </p>
                  <a 
                    href="tel:+5564981249199"
                    className="inline-flex items-center text-red-600 hover:text-red-700 font-medium transition-colors"
                  >
                    <Phone className="h-4 w-4 mr-2" />
                    (64) 98124-9199
                  </a>
                </div>

                <div className="bg-gray-50 rounded-xl p-6 text-center">
                  <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Mail className="h-6 w-6 text-blue-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Email</h4>
                  <p className="text-gray-600 mb-3">
                    Envie sua dúvida por email
                  </p>
                  <a 
                    href="mailto:convenioquiroferreira@gmail.com"
                    className="inline-flex items-center text-blue-600 hover:text-blue-700 font-medium transition-colors"
                  >
                    <Mail className="h-4 w-4 mr-2" />
                    Enviar Email
                  </a>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="text-center mt-8 pt-6 border-t border-gray-200">
              <img
                src="/logo_quiroferreira.svg"
                alt="Logo Quiro Ferreira"
                className="w-32 mx-auto mb-4 opacity-60"
              />
              <p className="text-gray-500 text-sm">
                Obrigado pela sua paciência. Voltaremos em breve com novidades!
              </p>
            </div>
          </div>
        </div>

        {/* Additional Info */}
        <div className="mt-6 text-center">
          <p className="text-gray-400 text-sm">
            Esta página é atualizada automaticamente. Não é necessário recarregar.
          </p>
        </div>
      </div>
    </div>
  );
};

export default MaintenancePage;