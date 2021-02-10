#############################################
"""
    File name: main.py
    Project name: three-ciphers
    Author: Tomasz Jasiński
    Python Version: 3.8
    Description:
"""

# TODO: documentation and some better menu

#############################################

import PySimpleGUI as sg

from symmetric_cipher import SymmetricCipher
from asymmetric_cipher import AsymmetricCipher


def simplegui_menu():
    global symmetric_cipher, asymmetric_cipher
    symmetric_algorithms = [key for key in SymmetricCipher.encryption_algorithms.keys()]

    sg.theme('DarkGrey2')
    sg.SetOptions(
        element_padding=(
            (10, 10),
            (10, 20)
        ),
        font=('Verdana', 10)
    )

    def text_label(text):
        return sg.Text(
            text + ':',
            justification='r',
            size=(15, 1)
        )

    def twoline_text_label(text):
        return sg.Text(
            text + ':',
            justification='r',
            size=(15, 2)
        )

    frame_layout = [
        [
            text_label('Encryption'),
            sg.Radio(
                text='Symmetric',
                group_id='Encryption',
                key='-SYMMETRIC-',
                enable_events=True
            ),
            sg.Radio(
                text='Asymmetric',
                group_id='Encryption',
                key='-ASYMMETRIC-',
                enable_events=True
            )
        ],

        [
            text_label('Plaintext'),
            sg.Input(
                key='-PLAINTEXT-',
                enable_events=True
            )
        ],

        [
            twoline_text_label('Encryption\nAlgorithm'),
            sg.Combo(
                values=[
                    k for k in SymmetricCipher.encryption_algorithms.keys()
                ],
                default_value=[],
                size=(10, 5),
                key='-CRYPT-ALGORITHM-',
                readonly=True,
                enable_events=True
            ),
            text_label('Key Size'),
            sg.Combo(
                [],
                default_value=[],
                size=(5, 5),
                key='-CRYPT-KEY-SIZE-',
                readonly=True,
                enable_events=True
            ),
        ],

        [
            twoline_text_label('Auth\nAlgorithm'),
            sg.Combo(
                values=[
                    k for k in AsymmetricCipher.auth_algorithms.keys()
                ],
                default_value=[],
                size=(10, 5),
                key='-AUTH-ALGORITHM-',
                readonly=True,
                enable_events=True
            )
        ],

        [
            text_label(f'Secret Key'),
            sg.Input(
                key='-SECRET-KEY-',
                enable_events=True
            )
        ]
    ]
    layout = [
        [
            sg.Frame(
                title='',
                layout=frame_layout,
                pad=(10, 10),
                border_width=0
            )
        ],

        [
            sg.Button(
                'Encrypt',
                button_color=('white', '#28965A'),
                size=(20, 2),
                pad=((10, 11), 10),
                disabled=True,
                bind_return_key=True
            ),
            sg.Button(
                'Decrypt',
                button_color=('white', 'firebrick3'),
                size=(20, 2),
                pad=(10, 10),
                disabled=True
            ),
            sg.Button(
                'Random Key',
                size=(20, 2),
                pad=((11, 10), 10),
                disabled=True
            )
        ],

        [
            sg.Output(
                key='-OUTPUT-',
                size=(58, 30),
                pad=(10, (10, 20)),
                font='Consolas 12',
                echo_stdout_stderr=True
            )
        ]
    ]

    window = sg.Window(
        'CryptoPlayground',
        layout
    )

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED or event == 'Exit':
            break

        elif event == '-ASYMMETRIC-':
            window['-SECRET-KEY-'].hide_row()
            window['-AUTH-ALGORITHM-'].unhide_row()

            window['-CRYPT-ALGORITHM-'].update(
                [],
                values=[
                    k for k in AsymmetricCipher.encryption_algorithms.keys()
                ]
            )

        elif event == '-SYMMETRIC-':
            window['-SECRET-KEY-'].unhide_row()
            window['-AUTH-ALGORITHM-'].hide_row()
            window['-CRYPT-ALGORITHM-'].update(
                [],
                values=[
                    k for k in SymmetricCipher.encryption_algorithms.keys()
                ]
            )

        elif event == '-CRYPT-ALGORITHM-':
            if values['-SYMMETRIC-']:
                symmetric_cipher = SymmetricCipher(
                    encryption_algorithm=SymmetricCipher.encryption_algorithms[
                        values['-CRYPT-ALGORITHM-']
                    ]
                )
                window['-CRYPT-KEY-SIZE-'].update(
                    [],
                    values=[
                        ks for ks in list(
                            symmetric_cipher.encryption_algorithm.key_sizes
                        )
                    ]
                )

            elif values['-ASYMMETRIC-']:
                window['-AUTH-ALGORITHM-'].update(set_to_index=1)
                asymmetric_cipher = AsymmetricCipher(
                    encryption_algorithm=AsymmetricCipher.encryption_algorithms[
                        values['-CRYPT-ALGORITHM-']
                    ],
                    auth_algorithm=AsymmetricCipher.auth_algorithms[
                        values['-CRYPT-ALGORITHM-']
                    ]
                )
                window['-CRYPT-KEY-SIZE-'].update(
                    [],
                    values=[
                        ks for ks in list(
                            asymmetric_cipher.encryption_algorithm.key_sizes
                        )

                    ]
                )

            window['Random Key'].update(disabled=True)
            window['Encrypt'].update(disabled=True)

        elif event == '-AUTH-ALGORITHM-':
            asymmetric_cipher = AsymmetricCipher(
                encryption_algorithm=AsymmetricCipher.encryption_algorithms[
                    values['-CRYPT-ALGORITHM-']
                ],
                auth_algorithm=AsymmetricCipher.auth_algorithms[
                    values['-AUTH-ALGORITHM-']
                ]
            )

        elif event == '-CRYPT-KEY-SIZE-':
            if values['-SYMMETRIC-']:
                window['Random Key'].update(disabled=False)
                if len(values['-SECRET-KEY-']) * 8 == values['-CRYPT-KEY-SIZE-']:
                    window['Encrypt'].update(disabled=False)
                else:
                    window['Encrypt'].update(disabled=True)

            elif values['-ASYMMETRIC-']:
                window['Encrypt'].update(disabled=False)

        elif event == '-SECRET-KEY-':
            if len(values['-SECRET-KEY-']) * 8 == values['-CRYPT-KEY-SIZE-']:
                window['Encrypt'].update(disabled=False)
            else:
                window['Encrypt'].update(disabled=True)

        elif event == 'Encrypt':
            if values['-SYMMETRIC-']:
                (stored_key,
                 stored_iv,
                 stored_ciphertext) = symmetric_cipher.encrypt(
                    values['-PLAINTEXT-'],
                    values['-SECRET-KEY-']
                )
                print('ENCRYPTION RESULT'.center(55, '#'))
                print('Secret Key'.center(50, '-'))
                print(stored_key, '\n')
                print('Initialization Vector'.center(50, '-'))
                print(stored_iv, '\n')
                print('Encrypted Message'.center(50, '-'))
                print(stored_ciphertext, '\n')

            elif values['-ASYMMETRIC-']:
                (private_key,
                 public_key,
                 signature_key,
                 verification_key) = asymmetric_cipher.generate_keys(
                    values['-CRYPT-KEY-SIZE-']
                )
                signature = asymmetric_cipher.sign(
                    values['-PLAINTEXT-'],
                    signature_key
                )
                stored_ciphertext = asymmetric_cipher.encrypt(
                    values['-PLAINTEXT-'],
                    public_key
                )
                print('ENCRYPTION RESULT'.center(55, '#'))
                print('Encrypted Message'.center(50, '-'))
                print(stored_ciphertext, '\n')
                print('Signature'.center(50, '-'))
                print(signature, '\n')

            window['Decrypt'].update(disabled=False)

        elif event == 'Decrypt':
            if values['-SYMMETRIC-']:
                decrypted_message = symmetric_cipher.decrypt(
                    (stored_iv, stored_ciphertext),
                    stored_key
                )
                print('DECRYPTION RESULT'.center(55, '#'))
                print('Decrypted Message'.center(50, '-'))
                print(decrypted_message, '\n')

            elif values['-ASYMMETRIC-']:
                decrypted_message = asymmetric_cipher.decrypt(
                    stored_ciphertext,
                    private_key
                )
                is_verified = asymmetric_cipher.verify(
                    decrypted_message,
                    signature,
                    verification_key
                )
                print('DECRYPTION RESULT'.center(55, '#'))
                print('Decrypted Message'.center(50, '-'))
                print(decrypted_message, '\n')
                print('Verified'.center(50, '-'))
                print(is_verified, '\n')

            window['Decrypt'].update(disabled=True)

        elif event == 'Random Key':
            window['-SECRET-KEY-'].update(
                symmetric_cipher.random_string(
                    int(values['-CRYPT-KEY-SIZE-'] / 8)
                )
            )
            window['Encrypt'].update(disabled=False)

        # print('\nEvent: ', event)
        # print('Values:')
        # for k in values:
        #     print(f'{k}: {values[k]}')
        # print('\n')

    window.close()


if __name__ == '__main__':
    simplegui_menu()
