// fixed local host thing
window.onload = () => {
    const socket = io.connect("http://localhost:8080", { transports: ['websocket'] });
};
