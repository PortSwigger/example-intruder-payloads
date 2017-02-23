java_import 'burp.IBurpExtender'
java_import 'burp.IIntruderPayloadGeneratorFactory'
java_import 'burp.IIntruderPayloadProcessor'
java_import 'burp.IIntruderPayloadGenerator'

# hard-coded payloads
# [in reality, you would use an extension for something cleverer than this]

PAYLOADS = [
  "|".bytes.to_a,
  "<script>alert(1)</script>".bytes.to_a
]

class BurpExtender
  include IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor

  #
  # implement IBurpExtender
  #

  def registerExtenderCallbacks(callbacks)
    # obtain an extension helpers object
    @helpers = callbacks.getHelpers

    # set our extension name
    callbacks.setExtensionName "Custom intruder payloads"

    # register ourselves as an Intruder payload generator
    callbacks.registerIntruderPayloadGeneratorFactory self

    # register ourselves as an Intruder payload processor
    callbacks.registerIntruderPayloadProcessor self
  end

  #
  # implement IIntruderPayloadGeneratorFactory
  #

  def getGeneratorName()
    "My custom payloads"
  end

  def createNewInstance(attack)
    # return a new IIntruderPayloadGenerator to generate payloads for this attack
    IntruderPayloadGenerator.new
  end

  #
  # implement IIntruderPayloadProcessor
  #

  def getProcessorName()
    "Serialized input wrapper"
  end

  def processPayload(currentPayload, originalPayload, baseValue)
    # decode the base value
    dataParameter = @helpers.bytesToString(
        @helpers.base64Decode(@helpers.urlDecode baseValue))

    # parse the location of the input string in the decoded data
    start = dataParameter.index("input=") + 6
    return currentPayload if start == -1

    prefix = dataParameter[0...start]
    end_ = dataParameter.index("&", start)
    end_ = dataParameter.length if end_ == -1

    suffix = dataParameter[end_...dataParameter.length]

    # rebuild the serialized data with the new payload
    dataParameter = prefix + @helpers.bytesToString(currentPayload) + suffix
    return @helpers.stringToBytes(
        @helpers.urlEncode(@helpers.base64Encode dataParameter))
  end
end

#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator
  include IIntruderPayloadGenerator

  def initialize()
    @payloadIndex = 0
  end

  def hasMorePayloads()
    @payloadIndex < PAYLOADS.length
  end

  def getNextPayload(baseValue)
    payload = PAYLOADS[@payloadIndex]
    @payloadIndex = @payloadIndex + 1

    return payload
  end

  def reset()
    @payloadIndex = 0
  end
end
