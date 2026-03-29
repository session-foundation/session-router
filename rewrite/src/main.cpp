#include <sr/node/node.hpp>

#include <csignal>
#include <iostream>

static sr::node::Node* g_node = nullptr;

static void signal_handler(int sig) {
    if (g_node) {
        std::cout << "\nReceived signal " << sig << ", shutting down...\n";
        g_node->stop();
    }
}

int main(int argc, char** argv) {
    try {
        auto config = sr::node::Config::from_args(argc, argv);

        sr::node::Node node{std::move(config)};
        g_node = &node;

        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        node.run();

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
