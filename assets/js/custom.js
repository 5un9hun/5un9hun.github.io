start_rotation()

function start_rotation() {
    var elements = document.getElementsByClassName('rotation');
    for (var i=0; i<elements.length; i++) {
        var toRotate = elements[i].getAttribute('data-type');
        var period = elements[i].getAttribute('data-period');
        if (toRotate) {
          new TxtType(elements[i], JSON.parse(toRotate), period);
        }
    }
    // INJECT CSS
    /*var css = document.createElement("style");
    css.innerHTML = ".rotation > .wrap { border-right: 0.08em solid #fff }";
    document.body.appendChild(css);*/
};