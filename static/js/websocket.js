// fixed local host thing
window.onload = () => {
    const socket = io.connect(`${window.location.protocol}//${window.location.hostname}`, { transports: ['websocket'] });
};

