#include <boost/beast.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <memory>

// Определение пространств имён для удобства использования.
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json;
namespace http = boost::beast::http;

// Класс "Ответ от Сервера" представляет собой структуру ответа сервера.
class ServerResponse {
public:
    bool status; // Статус успешности выполнения запроса.
    std::optional<std::string> message; // Сообщение об ошибке, если оно есть.
    json data; // Данные, полученные от сервера в формате JSON.

    // Конструктор класса, инициализирующий поля класса.
    ServerResponse(bool status, std::optional<std::string> message, json data)
        : status(status), message(message), data(data) {}
};

// Класс "Сборщик и исполнитель запросов" отвечает за создание и выполнение HTTP-запросов.
class RequestExecutor {
private:
    // Приватные поля класса для хранения состояния объекта.
    boost::asio::io_context& ioc_;
    ssl::context ssl_context_;
    tcp::resolver resolver_;
    std::unique_ptr<tcp::socket> tcp_socket_;
    std::unique_ptr<ssl::stream<tcp::socket>> ssl_socket_;
    std::string host_;
    std::string port_;
    std::string target_;
    int version_;
    http::verb method_;
    std::vector<std::pair<std::string, std::string>> headers_;
    json body_;
    bool verify_ssl_;

public:
    // Конструктор класса, инициализирующий контекст ввода-вывода и SSL-контекст.
    RequestExecutor(boost::asio::io_context& ioc)
        : ioc_(ioc), ssl_context_(ssl::context::sslv23_client), resolver_(ioc), version_(11), verify_ssl_(false) {}

    // Методы для инициализации параметров запроса.
    void set_url(const std::string& host, const std::string& port, const std::string& target) {
        host_ = host;
        port_ = port;
        target_ = target;
    }

    void set_method(http::verb method) {
        method_ = method;
    }

    void add_header(const std::string& name, const std::string& value) {
        headers_.emplace_back(name, value);
    }

    void set_body(const json& body) {
        body_ = body;
    }

    void set_verify_certificate(bool verify) {
        verify_ssl_ = verify;
    }

    void connect(const tcp::resolver::results_type& results) {
        if (verify_ssl_) {
            ssl_socket_ = std::make_unique<ssl::stream<tcp::socket>>(ioc_, ssl_context_);
            if (!SSL_set_tlsext_host_name(ssl_socket_->native_handle(), host_.c_str())) {
                throw boost::system::system_error{ boost::asio::error::operation_not_supported };
            }
            boost::asio::connect(ssl_socket_->next_layer(), results.begin(), results.end());
            ssl_socket_->handshake(ssl::stream_base::client);
        }
        else {
            tcp_socket_ = std::make_unique<tcp::socket>(ioc_);
            boost::asio::connect(*tcp_socket_, results.begin(), results.end());
        }
    }

    void send_request(const http::request<http::string_body>& req) {
        if (verify_ssl_) {
            http::write(*ssl_socket_, req);
        }
        else {
            http::write(*tcp_socket_, req);
        }
    }

    http::response<http::dynamic_body> receive_response() {
        boost::beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        if (verify_ssl_) {
            http::read(*ssl_socket_, buffer, res);
        }
        else {
            http::read(*tcp_socket_, buffer, res);
        }
        return res;
    }

    void close_connection() {
        boost::system::error_code ec;
        if (verify_ssl_) {
            ssl_socket_->shutdown(ec);
        }
        else {
            tcp_socket_->shutdown(tcp::socket::shutdown_both, ec);
        }
        if (ec && ec != boost::asio::error::not_connected) {
            throw boost::system::system_error{ ec };
        }
    }

    // Метод выполнения запроса
    ServerResponse execute() {
        boost::system::error_code ec;
        try {
            auto const results = resolver_.resolve(host_, port_);
            connect(results);

            http::request<http::string_body> req{ method_, target_, version_ };
            req.set(http::field::host, host_);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            for (const auto& header : headers_) {
                req.set(header.first, header.second);
            }
            req.body() = body_.dump();
            req.prepare_payload();

            send_request(req);
            auto res = receive_response();
            close_connection();

            // Проверка на наличие ошибок сети
            if (!ec) {
                // Обработка ответа
                if (res.result() == http::status::ok) {
                    auto body = boost::beast::buffers_to_string(res.body().data());
                    json data = json::parse(body);
                    return ServerResponse(true, std::nullopt, data);
                }
                else {
                    // Обработка неудачного статуса ответа
                    std::string error_message = "HTTP error: " + std::to_string(res.result_int());
                    return ServerResponse(false, error_message, nullptr);
                }
            }
            else {
                // Обработка ошибок сети
                return ServerResponse(false, ec.message(), nullptr);
            }
        }
        catch (const boost::system::system_error& e) {
            // Обработка ошибок сети
            return ServerResponse(false, e.what(), nullptr);
        }
        catch (const std::exception& e) {
            // Обработка других исключений
            return ServerResponse(false, e.what(), nullptr);
        }
    }
};

// Пример использования класса для выполнения HTTP-запроса.
int main() {
    try {
        // Инициализация контекста ввода-вывода.
        boost::asio::io_context ioc;

        // Создание объекта исполнителя запросов.
        RequestExecutor executor(ioc);

        // Установка параметров запроса.
        executor.set_url("httpbin.org", "80", "/get");
        executor.set_method(http::verb::get);
        executor.add_header("Accept", "application/json");
        executor.set_verify_certificate(false); // Отключение проверки SSL-сертификата.

        // Выполнение запроса и получение ответа.
        ServerResponse response = executor.execute();

        // Обработка ответа от сервера.
        if (response.status) {
            // В случае успешного выполнения запроса выводим полученные данные.
            std::cout << "Response: " << response.data << std::endl;
        }
        else {
            // В случае ошибки выводим сообщение об ошибке.
            std::cerr << "Error: " << *response.message << std::endl;
        }
    }
    catch (const std::exception& e) {
        // Обработка исключений, возникающих при выполнении программы.
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    // Остановка программы для просмотра результатов.
    system("pause");
    return 0;
}
