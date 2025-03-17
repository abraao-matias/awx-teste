# awx-teste

win_test.yml
---
- name: Teste de Conexão com Windows
  hosts: all
  gather_facts: no
  tasks:
    - name: Executar comando whoami no Windows
      ansible.windows.win_command: whoami
      register: whoami_output
    - name: Mostrar resultado
      ansible.builtin.debug:
        msg: "Usuário atual: {{ whoami_output.stdout }}"

snapshot_hyperv.yml

---
- name: Criar snapshot da VM windows10 no Hyper-V
  hosts: 192.168.217.1
  tasks:
    - name: Criar checkpoint da VM windows10
      ansible.windows.win_powershell:
        script: |
          try {
            $vmName = "windows10"
            $snapshotName = "Snapshot-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss')"
            Checkpoint-VM -Name $vmName -SnapshotName $snapshotName -ErrorAction Stop
            Write-Output "Snapshot criado: $snapshotName"
          } catch {
            Write-Error "Erro ao criar snapshot: $_"
            exit 1
          }
      register: checkpoint_result

    - name: Exibir resultado do snapshot
      ansible.builtin.debug:
        msg: "{{ checkpoint_result.output }}"


identificar_processos_ativos.yml

---
- name: Identify Services Before Update
  hosts: 192.168.217.2
  gather_facts: yes
  become: yes  # Executa com privilégios elevados
  become_method: runas  # Método para elevação no Windows
  become_user: tsuna  # Usuário para elevação

  tasks:
    - name: Get running services before update
      win_shell: |
        Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType, @{Label="LogonAs";Expression={$_.ServiceHandle}} | Format-Table -AutoSize | Out-String -Width 4096
      register: services_before
      changed_when: false
      # Coleta serviços com as colunas: Nome, Descrição (DisplayName), Status, Tipo de Inicialização (StartType), e tenta obter "Fazer Logon Como"

    - name: Count services before update
      set_fact:
        service_count_before: "{{ services_before.stdout_lines | length - 3 }}"
      # Subtrai 3 para ignorar cabeçalho do Format-Table

    - name: Debug service count before update
      debug:
        msg: "Number of services before update: {{ service_count_before }}"

    - name: Debug all services before update
      debug:
        msg: "List of all services before update:\n{{ services_before.stdout }}"
      # Exibe a lista completa no log

    - name: Ensure Desktop directory exists
      win_file:
        path: C:\Users\tsuna\Desktop
        state: directory
      # Garante que o diretório Desktop exista

    - name: Save service count to file
      win_shell: echo {{ service_count_before }} > C:\Users\tsuna\Desktop\service_count_before.txt
      # Salva o número de serviços

    - name: Save full service list to file
      win_copy:
        content: "{{ services_before.stdout }}"
        dest: C:\Users\tsuna\Desktop\services_before_full.txt
      # Usa win_copy para salvar a lista completa de serviços


verificar_lista_completa_reboot.yml

---
- name: Identify Services After Reboot and Compare
  hosts: 192.168.217.2
  gather_facts: yes
  become: yes  # Executa com privilégios elevados
  become_method: runas  # Método para elevação no Windows
  become_user: tsuna  # Usuário para elevação

  tasks:
    - name: Get all services after reboot
      win_shell: |
        Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType, @{Label="LogonAs";Expression={$_.ServiceHandle}} | Format-Table -AutoSize | Out-String -Width 4096
      register: services_after
      changed_when: false
      # Coleta serviços com as colunas: Nome, Descrição (DisplayName), Status, Tipo de Inicialização (StartType), e tenta obter "Fazer Logon Como"

    - name: Count services after reboot
      set_fact:
        service_count_after: "{{ services_after.stdout_lines | length - 3 }}"
      # Subtrai 3 para ignorar cabeçalho do Format-Table

    - name: Debug service count after reboot
      debug:
        msg: "Number of services after reboot: {{ service_count_after }}"

    - name: Debug all services after reboot
      debug:
        msg: "List of all services after reboot:\n{{ services_after.stdout }}"

    - name: Ensure Desktop directory exists
      win_file:
        path: C:\Users\tsuna\Desktop
        state: directory
      # Garante que o diretório Desktop exista

    - name: Save service count to file
      win_shell: echo {{ service_count_after }} > C:\Users\tsuna\Desktop\service_count_after.txt
      # Salva o número de serviços

    - name: Clean service list for saving
      set_fact:
        cleaned_services_after: "{{ services_after.stdout | regex_replace('[<>|?*:\"]', '') | regex_replace('\r\n', '\n') }}"
      # Remove caracteres inválidos e normaliza quebras de linha

    - name: Debug cleaned service list
      debug:
        msg: "Cleaned service list:\n{{ cleaned_services_after }}"

    - name: Save full service list to file
      win_copy:
        content: "{{ cleaned_services_after }}"
        dest: C:\Users\tsuna\Desktop\services_after_full.txt
      # Usa win_copy para salvar a lista completa de serviços, agora limpa

    - name: Read service list before reboot from file
      win_shell: type C:\Users\tsuna\Desktop\services_before_full.txt
      register: services_before_raw
      changed_when: false

    - name: Debug raw service list before reboot
      debug:
        msg: "Raw service list before reboot:\n{{ services_before_raw.stdout }}"

    - name: Clean service list before reboot for parsing
      set_fact:
        cleaned_services_before: "{{ services_before_raw.stdout | regex_replace('[<>|?*:\"]', '') | regex_replace('\r\n', '\n') }}"

    - name: Debug cleaned service list before reboot
      debug:
        msg: "Cleaned service list before reboot:\n{{ cleaned_services_before }}"

    - name: Parse service list before reboot
      set_fact:
        services_before: "{{ cleaned_services_before | regex_findall('^(\\S+)\\s+(.+?)\\s+(Running|Stopped)\\s+(Auto|Manual|Disabled|Unknown)\\s+(\\S+)?\\s+(\\S+)?', multiline=True) | map('join', ' ') | list }}"
      # Captura nome, display name, status, start type, service type, e logon as (opcional)

    - name: Debug parsed services before reboot
      debug:
        msg: "Parsed services before reboot: {{ services_before }}"

    - name: Filter services that were Running before reboot
      set_fact:
        running_services_before: "{{ services_before | select('match', '.*\\sRunning\\s.*') | list }}"

    - name: Debug services that were Running before reboot
      debug:
        msg: "Services that were Running before reboot: {{ running_services_before }}"

    - name: Extract names of services that were Running before reboot
      set_fact:
        running_service_names_before: "{{ running_services_before | map('split', ' ') | map('first') | list }}"

    - name: Debug names of services that were Running before reboot
      debug:
        msg: "Names of services that were Running before reboot: {{ running_service_names_before }}"

    - name: Check Audiosrv specifically before reboot
      debug:
        msg: "Audiosrv state before reboot: {{ running_services_before | select('match', '^Audiosrv.*') | list }}"

    - name: Parse service list after reboot
      set_fact:
        services_after: "{{ cleaned_services_after | regex_findall('^(\\S+)\\s+(.+?)\\s+(Running|Stopped)\\s+(Auto|Manual|Disabled|Unknown)\\s+(\\S+)?\\s+(\\S+)?', multiline=True) | map('join', ' ') | list }}"

    - name: Debug parsed services after reboot
      debug:
        msg: "Parsed services after reboot: {{ services_after }}"

    - name: Filter services that are Stopped after reboot
      set_fact:
        stopped_services_after: "{{ services_after | select('match', '.*\\sStopped\\s.*') | list }}"

    - name: Debug services that are Stopped after reboot
      debug:
        msg: "Services that are Stopped after reboot: {{ stopped_services_after }}"

    - name: Extract names of services that are Stopped after reboot
      set_fact:
        stopped_service_names_after: "{{ stopped_services_after | map('split', ' ') | map('first') | list }}"

    - name: Debug names of services that are Stopped after reboot
      debug:
        msg: "Names of services that are Stopped after reboot: {{ stopped_service_names_after }}"

    - name: Check Audiosrv specifically after reboot
      debug:
        msg: "Audiosrv state after reboot: {{ stopped_services_after | select('match', '^Audiosrv.*') | list }}"

    - name: Find services that changed from Running to Stopped
      set_fact:
        changed_services: "{{ running_service_names_before | intersect(stopped_service_names_after) | list }}"

    - name: Debug services that changed from Running to Stopped
      debug:
        msg: "Services that changed from Running to Stopped: {{ changed_services }}"

    - name: Get full details of changed services from after reboot
      set_fact:
        changed_services_full: "{{ services_after | select('match', '^(' + (changed_services | join('|')) + ')\\s+.*') | list }}"

    - name: Debug full details of changed services
      debug:
        msg:
          - "Changed services with full details: {{ changed_services_full }}"
          - "Total Running services before reboot: {{ running_services_before | length }}"
          - "Total Stopped services after reboot: {{ stopped_services_after | length }}"

    - name: Save changed services to file with proper line endings
      win_copy:
        content: "{{ changed_services_full | join('\r\n') if changed_services_full | length > 0 else 'No services changed' }}"
        dest: C:\Users\tsuna\Desktop\diferenca_de_processos.txt
      # Usa \r\n para quebras de linha no formato Windows


reboot_windows_machine2.yml

---
- name: Reboot Windows Machine with Auto-Login
  hosts: 192.168.217.2
  gather_facts: no
  become: yes
  become_method: runas
  become_user: tsuna

  tasks:
    - name: Ensure user tsuna password is set in the playbook (for auto-login)
      ansible.builtin.set_fact:
        tsuna_password: "{{ tsuna_password | default('123') }}"
      # Substitua 'YOUR_PASSWORD_HERE' pela senha do usuário tsuna ou passe-a via variável segura (ex.: Ansible Vault)

    - name: Enable auto-login by setting registry values
      win_regedit:
        path: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
        name: "{{ item.name }}"
        data: "{{ item.data }}"
        type: string
      loop:
        - { name: "AutoAdminLogon", data: "1" }  # Habilita o login automático
        - { name: "DefaultUserName", data: "tsuna" }  # Define o usuário
        - { name: "DefaultPassword", data: "{{ tsuna_password }}" }  # Define a senha
      # Configura o login automático no Registro

    - name: Reboot the machine
      win_reboot:
        msg: "Rebooting to apply changes with auto-login"
        reboot_timeout: 600
      # Reinicia a máquina e aguarda até 10 minutos para ela voltar
tsuna@awx:/var/lib/awx/projects/local_playbooks$

windows_patch.yml

---
- name: Apply Windows Patches and Log Installed KBs
  hosts: 192.168.217.2  # Substitua por seu grupo de hosts no inventário AWX
  gather_facts: no
  become: yes
  become_method: runas
  become_user: SYSTEM  # Usa o contexto SYSTEM para instalar atualizações

  tasks:
    - name: Verify WinRM connectivity
      ansible.windows.win_ping:
      register: winrm_result
      failed_when: winrm_result.failed
      # Verifica a conectividade WinRM antes de prosseguir

    - name: Get current date and time for log file
      ansible.windows.win_shell: |
        $date = Get-Date -Format "yyyyMMdd-HHmm"
        echo $date
      register: current_date_time
      changed_when: false
      # Obtém a data e hora atual usando PowerShell com formato seguro

    - name: Debug raw date output
      ansible.builtin.debug:
        msg: "Raw date output: {{ current_date_time.stdout }}"
      # Depuração para verificar o valor retornado com quebras de linha

    - name: Clean the date output by trimming newlines
      ansible.builtin.set_fact:
        cleaned_date: "{{ current_date_time.stdout | trim }}"
      # Remove quebras de linha e espaços em branco do valor retornado

    - name: Debug cleaned date
      ansible.builtin.debug:
        msg: "Cleaned date: {{ cleaned_date }}"
      # Depuração para verificar o valor após limpeza

    - name: Set log file paths with cleaned date
      ansible.builtin.set_fact:
        log_path: "C:\\Windows\\Logs\\WindowsUpdate\\patch_log_{{ cleaned_date }}.txt"
        kb_log_path: "C:\\Users\\tsuna\\Desktop\\installed_kbs_{{ cleaned_date }}.txt"
      # Define os caminhos dos logs usando a data limpa

    - name: Debug log paths
      ansible.builtin.debug:
        msg:
          - "Log path: {{ log_path }}"
          - "KB log path: {{ kb_log_path }}"
      # Depuração para verificar os caminhos gerados

    - name: Ensure logging directory exists
      ansible.windows.win_file:
        path: C:\Windows\Logs\WindowsUpdate
        state: directory
      # Cria o diretório para logs gerais, se não existir

    - name: Ensure Desktop directory exists
      ansible.windows.win_file:
        path: C:\Users\tsuna\Desktop
        state: directory
      # Garante que a área de trabalho do tsuna exista

    - name: Check for available updates
      ansible.windows.win_updates:
        category_names:
          - CriticalUpdates
          - SecurityUpdates
          - UpdateRollups
          - Updates  # Inclui atualizações genéricas, como visualizações
          - DefinitionUpdates
        state: searched
        log_path: "{{ log_path }}"
      register: update_search
      # Busca todas as atualizações disponíveis no Windows Update

    - name: Debug available updates (detailed)
      ansible.builtin.debug:
        msg:
          - "Found {{ update_search.updates | length }} updates to install"
          - "Available updates: {{ update_search.updates | to_json }}"
      # Exibe detalhes completos das atualizações encontradas

    - name: Install updates
      ansible.windows.win_updates:
        category_names:
          - CriticalUpdates
          - SecurityUpdates
          - UpdateRollups
          - Updates  # Inclui atualizações genéricas, como visualizações
          - DefinitionUpdates
        state: installed
        log_path: "{{ log_path }}"
        reboot: yes  # Reinicia automaticamente se necessário
        reboot_timeout: 3600  # 60 minutos para evitar timeouts
      register: update_install
      # Instala todas as atualizações das categorias especificadas

    - name: Debug installation result (detailed)
      ansible.builtin.debug:
        msg:
          - "Installation completed. Reboot required: {{ update_install.reboot_required }}"
          - "Installed updates: {{ update_install.updates | to_json }}"
          - "Found update count: {{ update_install.found_update_count }}"
          - "Installed update count: {{ update_install.installed_update_count }}"
          - "Failed update count: {{ update_install.failed_update_count }}"
      # Exibe detalhes completos do resultado da instalação

    - name: Extract installed KBs
      ansible.builtin.set_fact:
        installed_kbs: "{{ update_install.updates | selectattr('kb', 'defined') | map(attribute='kb') | list }}"
      # Extrai os KB's das atualizações instaladas

    - name: Debug installed KBs
      ansible.builtin.debug:
        msg: "Installed KBs: {{ installed_kbs }}"
      # Exibe os KB's instalados para depuração

    - name: Save installed KBs to Desktop
      ansible.windows.win_copy:
        content: "{{ installed_kbs | join('\r\n') if installed_kbs | length > 0 else 'No KBs installed' }}"
        dest: "{{ kb_log_path }}"
      # Salva os KB's na área de trabalho do tsuna, com quebras de linha no formato Windows

    - name: Ensure updates are applied after reboot (if needed)
      ansible.windows.win_updates:
        category_names:
          - CriticalUpdates
          - SecurityUpdates
          - UpdateRollups
          - Updates
          - DefinitionUpdates
        state: installed
        log_path: "{{ log_path }}"
      when: update_install.reboot_required
      # Verifica atualizações pendentes após o reboot

    - name: Extract installed KBs after reboot (if needed)
      ansible.builtin.set_fact:
        installed_kbs_after_reboot: "{{ update_install.updates | selectattr('kb', 'defined') | map(attribute='kb') | list }}"
      when: update_install.reboot_required
      # Extrai os KB's após o reboot, se aplicável

    - name: Append installed KBs after reboot to Desktop (if needed)
      ansible.windows.win_copy:
        content: "{{ installed_kbs + installed_kbs_after_reboot | join('\r\n') if installed_kbs_after_reboot is defined and installed_kbs_after_reboot | length > 0 else installed_kbs | join('\r\n') }}"
        dest: "{{ kb_log_path }}"
      when: update_install.reboot_required
      # Adiciona os KB's pós-reboot ao arquivo na área de trabalho



