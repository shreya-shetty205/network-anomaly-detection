// Home Page 1 

$(function () {
    var owl = $('.testimonial-con .owl-carousel');
    owl.owlCarousel({
        margin: 30,
        nav: false,
        loop: true,
        dots: true,
        autoplay: true,
        autoplayTimeout: 8000,
        responsive: {
            0: {
                items: 1
            },
            576: {
                items: 1
            }
        }
    })
})