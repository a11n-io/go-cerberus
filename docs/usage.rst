Usage
=====

.. _import:

Import
------------

To use go-cerberus, import it in your go project:

.. code-block:: console

    import (
        cerberus "github.com/a11n-io/go-cerberus"
    )

Creating the client
-------------------

To create the client you will use the ``cerberus.NewClient(baseUrl, apiKey, apiSecret string)`` function:

.. code-block:: console

cerberusClient := cerberus.NewClient("https://cerberus-api.a11n.io", "YOUR_CERBERUS_API_KEY", "YOUR_CERBERUS_API_SECRET")

The ``baseUrl`` parameter could be the hosted cloud API.
The ``apiKey`` and ``apiSecret`` parameters are generated on the cerberus dashboard for the app you're developing against.
