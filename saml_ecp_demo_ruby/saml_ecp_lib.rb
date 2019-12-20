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

  # FUTURE IDP_METADATA_FILE       = "/etc/httpd/saml2/idp-metadata.xml".freeze
  IDP_METADATA_FILE       = "./idp-metadata.xml".freeze # JJV Temp testing

  class EcpFLowError < StandardError; end

  class EcpFlow
    attr_reader :sp_resource_uri,  :sp_resource,
                :idp_endpoint_uri, :idp_endpoint,
                :user, :password, :idp_auth_method, :log_categories

    attr_accessor :sp_resource_http, :http_idp_endpoint, :paos_request_text, :paos_request_xml, :provider_name,
      :sp_response_consumer_url, :sp_message_id, :sp_is_passive, :sp_issuer, :sp_relay_state, :sp_authn_request_xml,
      :idp_response_text, :idp_response_xml, :idp_assertion_consumer_url, :idp_request_authenticated,
      :idp_saml_response_xml, :idp_saml_response_status_xml, :idp_saml_response_status_code,
      :idp_saml_response_status_code2, :idp_saml_response_status_msg, :idp_saml_response_status_detail,
      :sp_response_xml, :user_attrs

    def initialize(user, password, idp_auth_method)
      # HTTP session used to perform HTTP request/response

      @sp_resource = "https://#{Socket.gethostname}/saml_login" # When the client is also the MiQ appliance and not my MAC :)
      @sp_resource = 'https://joev-saml.jvlcek.redhat.com/saml_login'
      @idp_endpoint = nil

      @user = user
      @password = password
      @user_attrs = nil
      @idp_auth_method = idp_auth_method
      @log_categories = %w[http-lowlevel http-content sp-resource http-request-response message-info]
  
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
      validate_idp_response
      build_sp_response
      # JJV send_sp_response
      @user_attrs = get_user_attrs
      print_user_attrs
      require 'pry'; binding.pry # JJV
    end

    def ecp_issues_request_to_sp
      puts "\n=== ECP Issues HTTP Request to Service Provider ==="

      puts "JJV ZZZ 0.0 #{File.basename(__FILE__)} / #{__method__} @sp_resource ->#{@sp_resource}<-"
      @sp_resource_uri = URI.parse(sp_resource)
      @sp_resource_http = Net::HTTP.new(@sp_resource_uri.host, @sp_resource_uri.port)
      @sp_resource_http.use_ssl = true
      @sp_resource_http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      puts "JJV ZZZ 0.0 #{File.basename(__FILE__)} / #{__method__} @sp_resource_uri.request_uri ->#{@sp_resource_uri.request_uri}<-"
      request = Net::HTTP::Get.new(@sp_resource_uri.request_uri)
      request["Accept"] = "text/html, application/vnd.paos+xml"
      request["PAOS"]   = 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'

      response = @sp_resource_http.request(request)

      @paos_request_text = response.body
    end

    def process_paos_request
      puts "\n=== Process PAOS request from SP ==="

      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} @paos_request_text ->#{@paos_request_text}<-"

      @paos_request_xml = Nokogiri.XML(@paos_request_text)

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

     # JJV IDP_METADATA_FILE       = "/etc/httpd/saml2/idp-metadata.xml".freeze
      @idp_endpoint = Nokogiri::XML(File.read(IDP_METADATA_FILE)).at_xpath("/*/*/*/*/@Location").value

      puts "Using IdP endpoint: ->#{@idp_endpoint}<-"
    end

    def build_authn_request_for_idp
      puts "\n=== Build Authn Requst For Idp by removing Header from PAOS SOAP envelope ==="

      @idp_request_xml = @paos_request_xml.dup
      xpath_expr = '/soap:Envelope/soap:Header'
      matches = @idp_request_xml.xpath(xpath_expr, NAMESPACES)

      # matches.each { |e| e.remove }
      matches.each(&:remove)

      @idp_request_text = @idp_request_xml.inner_html.encode('utf-8')
    end

    def send_authn_request_to_idp
      puts "\n=== ECP sends <AuthnRequest> to IdP with authentication ==="

      puts "JJV ZZZ 0.0 #{File.basename(__FILE__)} / #{__method__} @idp_endpoint ->#{@idp_endpoint}<-"
      @idp_endpoint_uri = URI.parse(@idp_endpoint)
      @idp_endpoint_http = Net::HTTP.new(@idp_endpoint_uri.host, @idp_endpoint_uri.port)
  
      request = Net::HTTP::Post.new(@idp_endpoint)

      request["Content-Type"] = "text/xml"
      request.basic_auth(@user, @password)
      request.body = @idp_request_text

      response = @idp_endpoint_http.request(request)

      @idp_response_text = response.body

      puts "SOAP message from ECP to IdP\n ->#{@idp_response_text}<-"
    end

    def process_idp_response
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

      puts_idp_response_info(@log_categories, __method__)
    end

    def validate_idp_response
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      if (@sp_response_consumer_url != @idp_assertion_consumer_url)
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} @sp_response_consumer_url != @idp_assertion_consumer_url"

        err_msg = "SP responseConsumerURL MUST match IdP AssertionConsumerServiceURL but responseConsumerURL=#{@sp_response_consumer_url} AssertionConsumerServiceURL=#{ @idp_assertion_consumer_url}"
        @sp_response_xml = build_soap_fault('server', 'invalid response', err_msg)
        return false
      end

      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} @sp_response_consumer_url == @idp_assertion_consumer_url"
      true
    end

    def build_sp_response
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      return unless @sp_response_xml.nil?

      nsmap = @idp_response_xml.namespaces
      nsmap['xmlns:paos'] = NS_PAOS
      nsmap['xmlns:ecp'] = NS_ECP
      soap_ns = nsmap.detect { |n,v| v == NS_SOAP}.first.gsub("xmlns:","")

      puts "JJV 002 #{File.basename(__FILE__)} / #{__method__} nsmap \n#{nsmap}"

      builder = Nokogiri::XML::Builder.new do |xml| 
        xml[soap_ns].Envelope(nsmap) do |envelope|
          envelope[soap_ns].Header do |header|
            if @sp_message_id
              header["paos"].Response("#{soap_ns}:actor" => SOAP_ACTOR,
                                      "#{soap_ns}:mustUnderstand" => SOAP_MUST_UNDERSTAND,
                                      "paos:refToMessageID" => @sp_message_id)
            end
            if @sp_relay_state
              header["ecp"].RelayState(@sp_relay_state,
                                       "#{soap_ns}:actor" => SOAP_ACTOR,
                                       "#{soap_ns}:mustUnderstand" => SOAP_MUST_UNDERSTAND)
            end
          end # envelope
          envelope[soap_ns].Body
        end # xml
      end # builder

      builder.doc.xpath("//#{soap_ns}:Body").first  << @idp_saml_response_xml

      @sp_response_xml = builder.doc
    end

    def send_sp_response
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
      puts "\n=== Send PAOS response to SP, if successful SP resource is returned ==="

      # JJV @sp_response_consumer_url = "https://joev-saml.jvlcek.redhat.com/saml2/paosResponse"

      puts "=== PAOS response sent to SP ===\nSP Endpoint: #{@sp_response_consumer_url}"

      sp_response_consumer_url_uri = URI.parse(@sp_response_consumer_url)

      sp_response_consumer_url_http = Net::HTTP.new(sp_response_consumer_url_uri.host, sp_response_consumer_url_uri.port)
      sp_response_consumer_url_http.use_ssl = true
      sp_response_consumer_url_http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      # JJV request = Net::HTTP::Post.new(@sp_response_consumer_url)
      request = Net::HTTP::Post.new("/saml2/paosResponse")
      request["Content-Type"] = "application/vnd.paos+xml"
      request.body = @sp_response_xml.inner_html.encode('utf-8')

      response = sp_response_consumer_url_http.request(request)

      @sp_response_text = response.body

      require 'pry'; binding.pry # JJV
      puts "--- SP Resource ---\n#{@sp_response_text}"
    end

    def get_user_attrs
      @user_attrs = @sp_response_xml.xpath("//saml:Attribute").each_with_object({}) { |n,h| h[n["Name"]] = n.text }
      @user_attrs["groups"] = @sp_response_xml.xpath("//saml:Attribute[@Name='groups']").map(&:text)
      @user_attrs
    end

    private

    def build_soap_fault(fault_code, fault_string, detail=nil)
      puts "\n=== Build a SOAP Fault document and return it as a XML object. ==="

      builder = Nokogiri::XML::Builder.new { |xml|
        xml['soap'].Envelope("xmlns:soap" => NS_SOAP) { |envelope|
          envelope['soap'].Body { |body|
            body['soap'].Fault { |fault|
              fault.faultcode("soap:#{fault_code}")
              fault.faultstring(fault_string)
              fault.detail(detail) unless detail.nil?
            }
          }
        }
      }

      builder_xml = builder.to_xml.gsub!("soap:faultcode", "faultcode").gsub!("soap:faultstring", "faultstring").gsub!("soap:detail", "detail")

      return Nokogiri::XML(builder_xml)
    end

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
      soap_actor = get_xml_element_text(node, false, './@soap:actor')
      raise EcpFlowError, "#{description} is missing required soap:actor attribute" if soap_actor.nil?
      raise EcpFlowError, "#{description} %s has invalid soap:actor value: #{soap_actor}, expecting #{SOAP_ACTOR}" if soap_actor != SOAP_ACTOR

      soap_must_understand = get_xml_element_text(node, false, './@soap:mustUnderstand')
      raise EcpFlowError, "#{description} is missing required soap:mustUnderstand attribute" if soap_must_understand.nil?
      raise EcpFlowError, "#{description} has invalid soap:actor value: #{soap_must_understand}, expecting #{SOAP_MUST_UNDERSTAND}" if soap_must_understand != SOAP_MUST_UNDERSTAND
    end

    def puts_idp_response_info(log_categories, msg=nil)
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      puts msg unless msg.nil?
      puts "IdP SOAP Response Info:\n"
      puts "  SAML Status Code:           #{@idp_saml_response_status_code || 'None'}"
      puts "  SAML Status Code 2:         #{@idp_saml_response_status_code2 || 'None'}"
      puts "  SAML Status Message:        #{@idp_saml_response_status_msg || 'None'}"
      puts "  SAML Status Detail:         #{@idp_saml_response_status_detail || 'None'}"
      puts "  idp_assertion_consumer_url: #{@idp_assertion_consumer_url || 'None'}"
      puts "  idp_request_authenticated:  #{@idp_request_authenticated || 'None'}"
      puts "  SAML Response:\n%s\n #{@idp_saml_response_xml.to_s}" if log_categories.include?("saml-message")
    end

    def print_user_attrs
      @user_attrs.each { |n,v| printf "    %-13s %s\n", n, v }
    end

    def pp_xml_to_string(root) # format_xml_from_object
      root.to_s
    end

  end
end

if $PROGRAM_NAME == __FILE__

   # require 'pry'; binding.pry # JJV

  user            = 'jvlcek'
  password        = 'smartvm'
  idp_auth_method = 'basic'

  EcpDemo::EcpFlow.new(user, password, idp_auth_method).run
end

