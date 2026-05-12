<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('otp'); section>
<!-- template: login-email-otp.ftl -->

    <#if section="header">
        ${msg("emailOtpTitle")}
    <#elseif section="form">
        <form id="kc-email-otp-form" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
            <@field.input name="otp" label=msg("emailOtpLabel") autocomplete="one-time-code" fieldName="otp" autofocus=true />

            <@buttons.loginButton />
        </form>

        <#assign resendIn = (resendAvailableInSeconds!0)?number>
        <form id="kc-otp-resend-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" style="margin-top: 1rem;">
            <input type="hidden" name="resend" value="true" />
            <button type="submit" id="kc-otp-resend-button"
                    class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                    <#if resendIn gt 0>disabled</#if>>
                <#if resendIn gt 0>
                    <span id="kc-otp-resend-label">${msg("resendOtpAvailableIn", resendIn?c)}</span>
                <#else>
                    <span id="kc-otp-resend-label">${msg("resendOtpButton")}</span>
                </#if>
            </button>
        </form>

        <#if resendIn gt 0>
        <script>
            (function() {
                var remaining = ${resendIn?c};
                var button = document.getElementById('kc-otp-resend-button');
                var label = document.getElementById('kc-otp-resend-label');
                var readyText = "${msg('resendOtpButton')?no_esc}";
                var countdownTemplate = "${msg('resendOtpAvailableIn', '__SECS__')?no_esc}";
                var tick = function() {
                    remaining -= 1;
                    if (remaining <= 0) {
                        button.disabled = false;
                        label.textContent = readyText;
                        return;
                    }
                    label.textContent = countdownTemplate.replace('__SECS__', remaining);
                    window.setTimeout(tick, 1000);
                };
                window.setTimeout(tick, 1000);
            })();
        </script>
        </#if>
    </#if>
</@layout.registrationLayout>
