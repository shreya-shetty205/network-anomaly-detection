$(function () {
	$(document).on('click', '#submit', function () {
		if ($('#captcha_val').val() !== $('#captcha_text').val()) {
			$('#captcha_text').parent('div').append('<span class="error">Captch is not match</span>');
		} else {
			$("#contactpage").validate({
				submitHandler: function (e) {
					submitSignupFormNow($("#contactpage"))
				},
				rules: {
					fname: {
						required: true
					},
					email: {
						required: true,
						email: true
					},
					phone: {
						required: true,
						phone: true
					}
				},
				errorElement: "span",
				errorPlacement: function (e, t) {
					e.appendTo(t.parent())
				}
			});
			submitSignupFormNow = function (e) {
				var t = e.serialize();
				var n = "contact-form.php";
				$.ajax({
					url: n,
					type: "POST",
					data: t,
					dataType: "json",
					success: function (t) {
						if (t.status === "Success") {
							$("#form_result").html('<span class="form-success alert alert-success d-block">' + t.msg + "</span>");
						} else {
							$("#form_result").html('<span class="form-error alert alert-danger d-block">' + t.msg + "</span>")
						}
						$("#form_result").show();
					}
				});
				return false
			}
		}
	});

})