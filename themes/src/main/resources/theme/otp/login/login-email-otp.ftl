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
    </#if>
</@layout.registrationLayout>
