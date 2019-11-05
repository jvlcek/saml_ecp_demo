#!/usr/bin/env ruby

require 'json'
require 'net/http'
require 'openssl'
require 'uri'
require 'nokogiri'

module EcpDemo

  NS_ECP                  = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
  NS_PAOS                 = "urn:liberty:paos:2003-08".freeze
  NS_SOAP                 = "http://schemas.xmlsoap.org/soap/envelope/".freeze
  NS_SAMLP                = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
  NS_SAML                 = "urn:oasis:names:tc:SAML:2.0:assertion".freeze

  SOAP_ACTOR              = "http://schemas.xmlsoap.org/soap/actor/next".freeze
  SOAP_MUST_UNDERSTAND    = "1".freeze

  NAMESPACES              = { "ecp": NS_ECP, "paos": NS_PAOS, "soap": NS_SOAP, "samlp": NS_SAMLP, "saml": NS_SAML }.freeze

  VALID_LOG_CATEGORIES    = %w[sp-resource message-info saml-message http-request-response http-content http-lowlevel].freeze
  DEFAULT_LOG_CATEGORIES  = %w[sp-resource message-info saml-message http-request-response].freeze

  class EcpFLowError < StandardError; end

  class EcpFlow
    attr_reader :sp_resource_uri,  :sp_resource,
                :idp_endpoint_uri, :idp_endpoint,
                :user, :password, :idp_auth_method, :log_categories

    attr_accessor :sp_resouce_http, :http_idp_endpoint, :paos_request_text, :paos_request_xml, :provider_name,
      :sp_response_consumer_url, :sp_message_id, :sp_is_passive, :sp_issuer, :sp_relay_state, :sp_authn_request_xml,
      :idp_response_text, :idp_response_xml, :idp_assertion_consumer_url, :idp_request_authenticated,
      :idp_saml_response_xml, :idp_saml_response_status_xml, :idp_saml_response_status_code,
      :idp_saml_response_status_code2, :idp_saml_response_status_msg, :idp_saml_response_status_detail,
      :sp_response_xml

    def initialize(sp_resource, idp_endpoint, user, password, idp_auth_method, log_categories)
      # HTTP session used to perform HTTP request/response

      @sp_resource = sp_resource
      @sp_resource_uri = URI.parse(sp_resource)
      puts "sp_resource_uri.host                    ->#{sp_resource_uri.host}<-"
      puts "sp_resource_uri.port                    ->#{sp_resource_uri.port}<-"
      puts "sp_resource_uri.request_sp_resource_uri ->#{sp_resource_uri.request_uri}<-"
 
      @sp_resouce_http = Net::HTTP.new(sp_resource_uri.host, sp_resource_uri.port)
      @sp_resouce_http.use_ssl = true
      @sp_resouce_http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  
      @idp_endpoint = idp_endpoint
      @idp_endpoint_uri = URI.parse(@idp_endpoint)
      puts "idp_endpoint_uri.host        ->#{idp_endpoint_uri.host}<-"
      puts "idp_endpoint_uri.port        ->#{idp_endpoint_uri.port}<-"
      puts "idp_endpoint_uri.request_uri ->#{idp_endpoint_uri.request_uri}<-"
 
      @idp_endpoint_http = Net::HTTP.new(idp_endpoint_uri.host, idp_endpoint_uri.port)
  
      @user = user
      @password = password
      @idp_auth_method = idp_auth_method
      @log_categories = log_categories
  
      #### Collected Data ####
  
      # SP Request
      @paos_request_text = nil
      @paos_request_xml = nil
      @sp_response_consumer_url = nil
      @sp_message_id = nil
      @sp_is_passive = nil
      @sp_issuer = nil
      @sp_relay_state = nil
      @sp_authn_request_xml = nil
  
      # IdP Response
      @idp_response_text = nil
      @idp_response_xml = nil
      @idp_assertion_consumer_url = nil
      @idp_request_authenticated = nil
      @idp_saml_response_xml = nil
      @idp_saml_response_status_xml = nil
      @idp_saml_response_status_code = nil
      @idp_saml_response_status_code2 = nil
      @idp_saml_response_status_msg = nil
      @idp_saml_response_status_detail = nil
  
      # SP Response
      @sp_response_xml = nil
    end

    def run
        ecp_issues_request_to_sp
        process_paos_request
        determine_idp_endpoint
        build_authn_request_for_idp
        send_authn_request_to_idp
        process_idp_response

        return 1 # JJV

        validate_idp_response
        build_sp_response
        send_sp_response
    end

    def ecp_issues_request_to_sp
      puts "\n=== ECP Issues HTTP Request to Service Provider ==="

      request = Net::HTTP::Get.new(sp_resource_uri.request_uri)
      request["Accept"] = "text/html, application/vnd.paos+xml"
      request["PAOS"]   = 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'

      response = @sp_resouce_http.request(request)

      @paos_request_text = response.body
    end

    def process_paos_request
      puts "\n=== Process PAOS request from SP ==="

      @paos_request_xml = Nokogiri.XML(paos_request_text)

      @sp_response_consumer_url = get_xml_element_text(paos_request_xml, true,  '/soap:Envelope/soap:Header/paos:Request/@responseConsumerURL')
      @sp_message_id            = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/paos:Request/@messageID')
      @provider_name            = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:Request/@ProviderName')
      @sp_is_passive            = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:Request/@IsPassive')
      @sp_issuer                = get_xml_element_text(paos_request_xml, true,  '/soap:Envelope/soap:Header/ecp:Request/saml:Issuer')
      @sp_relay_state           = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:RelayState')
      @sp_authn_request_xml     = get_xml_element(paos_request_xml,      true,  '/soap:Envelope/soap:Body/samlp:AuthnRequest')

      log_paos_request
    end

    def determine_idp_endpoint
        puts "\n=== ECP Determines Identity Provider ==="
        puts "    STUB. For now use value passed on the command line."

        puts "Using IdP endpoint: ->#{idp_endpoint}<-"
    end

    def build_authn_request_for_idp
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

        @idp_request_xml = @paos_request_xml.dup
        xpath_expr = '/soap:Envelope/soap:Header'
        matches = @idp_request_xml.xpath(xpath_expr, NAMESPACES)

        # matches.each { |e| e.remove }
        matches.each(&:remove)

        @idp_request_text = @idp_request_xml.inner_html.encode('utf-8')
    end

    def send_authn_request_to_idp
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

        puts "\n=== ECP sends <AuthnRequest> to IdP with authentication ==="

        request = Net::HTTP::Post.new(@idp_endpoint)

        request["Content-Type"] = "text/xml"
        request.basic_auth(@user, @password)
        request.body = @idp_request_text

        response = @idp_endpoint_http.request(request)

        @idp_response_text = response.body

        puts "SOAP message from ECP to IdP\n ->#{@idp_response_text}<-"
    end

    def process_idp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
        puts "\n=== Processed response from IdP ==="

        @idp_response_xml = Nokogiri.XML(idp_response_text)


        @idp_request_authenticated = get_xml_element(@idp_response_xml, false, '/soap:Envelope/soap:Header/ecp:RequestAuthenticated')
        @idp_request_authenticated = false if @idp_request_authenticated.nil?

        @idp_saml_response_xml =     get_xml_element(@idp_response_xml, true, '/soap:Envelope/soap:Body/samlp:Response')
        ecp_response =               get_xml_element(@idp_response_xml, true, '/soap:Envelope/soap:Header/ecp:Response')

        validate_soap_attrs(ecp_response, 'IdP to ECP messge, ecp:Response')


        @idp_assertion_consumer_url =      get_xml_element_text(ecp_response, true, './@AssertionConsumerServiceURL')

        @idp_saml_response_status_code =   get_xml_element_text(@idp_saml_response_xml, true, './samlp:Status/samlp:StatusCode/@Value')
        @idp_saml_response_status_code2 =  get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value')
        @idp_saml_response_status_msg =    get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusMessage')
        @idp_saml_response_status_detail = get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusDetail')

        require 'pry'; binding.pry # JJV

        # JJV START HERE print("JJV 002 : %s @format_idp_response_info\n ->%s<-" % (inspect.stack()[0].function, self.format_idp_response_info(self.log_categories, description)), flush=true)
        # JJV START HERE LOG.info(self.format_idp_response_info(self.log_categories, description))

        puts "JJV 9.9 #{File.basename(__FILE__)} / #{__method__}"
    end

    def validate_idp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def build_sp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def send_sp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    private

    def get_xml_element(context_node, required, xpath_expr)
      matches = context_node.xpath(xpath_expr, NAMESPACES)

      if matches.count == 0
        raise EcpFlowError, "#{xpath_expr} not found " if required
        return nil
      end

      raise EcpFlowError, "found #{matches.count} multiple matches for #{xpath_expr}" if matches.count > 1

      return matches.first
    end

    def get_xml_element_text(context_node, required, xpath_expr)
      data = get_xml_element(context_node, required, xpath_expr)

      return data.children.first.text if data.respond_to?("children")

      return data.nil? ? nil : data.value
    end

    def log_paos_request
      puts "\n=== Log PAOS request from SP ==="

      puts "sp_response_consumer_url ->#{sp_response_consumer_url}<-"
      puts "sp_message_id            ->#{sp_message_id}<-"
      puts "provider_name            ->#{provider_name}<-"
      puts "sp_is_passive            ->#{sp_is_passive}<-"
      puts "sp_issuer                ->#{sp_issuer}<-"
      puts "sp_relay_state           ->#{sp_relay_state}<-"
      puts "sp_authn_request_xml     ->#{sp_authn_request_xml}<-"
      puts "=== End Log PAOS request from SP ===\n"
    end

    def validate_soap_attrs(node, description)
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      soap_actor = get_xml_element_text(node, false, './@soap:actor')
      require 'pry'; binding.pry # JJV
      raise EcpFlowError, "#{description} is missing required soap:actor attribute" if soap_actor.nil?
      raise EcpFlowError, "#{description} %s has invalid soap:actor value: #{soap_actor}, expecting #{SOAP_ACTOR}" if soap_actor != SOAP_ACTOR

      soap_must_understand = get_xml_element_text(node, false, './@soap:mustUnderstand')
      require 'pry'; binding.pry # JJV
      raise EcpFlowError, "#{description} is missing required soap:mustUnderstand attribute" if soap_must_understand.nil?
      raise EcpFlowError, "#{description} has invalid soap:actor value: #{soap_must_understand}, expecting #{SOAP_MUST_UNDERSTAND}" if soap_must_understand != SOAP_MUST_UNDERSTAND
    end
  end
end

if $PROGRAM_NAME == __FILE__

   # require 'pry'; binding.pry # JJV

  sp_resource     = 'https://joev-saml/saml_login'
  idp_endpoint    = 'http://joev-keycloak:8080/auth/realms/miq/protocol/saml'
  user            = 'jvlcek'
  password        = 'smartvm'
  idp_auth_method = 'basic'
  log_categories  = %w[http-lowlevel http-content sp-resource http-request-response message-info saml-message]

  EcpDemo::EcpFlow.new(sp_resource, idp_endpoint, user, password, idp_auth_method, log_categories).run
end

